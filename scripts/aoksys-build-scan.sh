#!/usr/bin/env bash
set -euo pipefail
export GOTOOLCHAIN=local CGO_ENABLED=0 GOFLAGS=-mod=readonly
mkdir -p downstream
go mod download
go mod verify
go install golang.org/x/vuln/cmd/govulncheck@v1.10.0
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
install_tool() {
    local name="$1" version="$2" archive="$3" checksums="$4" base="$5"
    curl -fsSL --retry 3 "$base/$archive" -o "$work/$archive"
    curl -fsSL --retry 3 "$base/$checksums" -o "$work/$checksums"
    (cd "$work" && awk -v n="$archive" '$2 == n || $2 == "*" n {print}' "$checksums" > selected && sha256sum -c selected)
    tar -xzf "$work/$archive" -C "$work" "$name"
    install -m 0755 "$work/$name" "$work/tool-$name"
}
install_tool syft 1.57.2 syft_1.57.2_linux_amd64.tar.gz syft_1.57.2_checksums.txt https://github.com/anchore/syft/releases/download/v1.57.2
install_tool trivy 0.76.2 trivy_0.76.2_Linux-64bit.tar.gz trivy_0.76.2_checksums.txt https://github.com/aquasecurity/trivy/releases/download/v0.76.2

status=PASS
if ! "$(go env GOPATH)/bin/govulncheck" ./... > downstream/govulncheck-source.txt 2>&1; then status=FAIL; fi
cat downstream/govulncheck-source.txt
for arch in amd64 arm64; do
    binary="downstream/helm-cm-push-linux-$arch"
    GOOS=linux GOARCH="$arch" go build -trimpath -o "$binary" ./cmd/helm-cm-push
    go version -m "$binary" > "downstream/go-buildinfo-$arch.txt"
    "$work/tool-syft" scan "file:$binary" -o "cyclonedx-json=downstream/sbom-$arch.cdx.json"
    jq -e '.bomFormat == "CycloneDX" and (.components | length > 0)' "downstream/sbom-$arch.cdx.json"
    if ! "$(go env GOPATH)/bin/govulncheck" -mode=binary "$binary" > "downstream/govulncheck-$arch.txt" 2>&1; then status=FAIL; fi
    cat "downstream/govulncheck-$arch.txt"
    "$work/tool-trivy" sbom --scanners vuln --format json --exit-code 0 --output "downstream/trivy-$arch.json" "downstream/sbom-$arch.cdx.json"
    jq -e '(.Results | type == "array")' "downstream/trivy-$arch.json"
    jq -r '[.Results[] | .Vulnerabilities[]? | .VulnerabilityID] | unique | length' "downstream/trivy-$arch.json" > "downstream/unique-findings-$arch.txt"
    printf '\nTrivy findings for %s:\n' "$arch"
    jq -r '.Results[] | .Vulnerabilities[]? | [.Severity, .VulnerabilityID, .PkgName, .InstalledVersion, (.FixedVersion // "")] | @tsv' "downstream/trivy-$arch.json"
    printf 'Unique findings: %s\n' "$(cat "downstream/unique-findings-$arch.txt")"
    if ! jq -e '[.Results[] | .Vulnerabilities[]? | select(.Severity == "HIGH" or .Severity == "CRITICAL")] | length == 0' "downstream/trivy-$arch.json" >/dev/null; then status=FAIL; fi
done
downstream/helm-cm-push-linux-amd64 --help >/dev/null
git diff --exit-code -- go.mod go.sum
git rev-parse HEAD > downstream/source-commit.txt
printf '%s\n' "$status" | tee downstream/security-status.txt
(cd downstream && sha256sum helm-cm-push-linux-* go-buildinfo-*.txt sbom-*.cdx.json trivy-*.json govulncheck-*.txt unique-findings-*.txt source-commit.txt security-status.txt > checksums.txt)
