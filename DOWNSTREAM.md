# Downstream security builds

This fork retains the upstream module path and the cm-push plugin name.

The hardening workflow resolves Go dependencies on hardening/aoksys, tests the
candidate with upstream Helm 3 and Helm 4 acceptance tests, then commits only
the validated go.mod and go.sum. It builds both Linux architectures and publishes
CycloneDX SBOMs, Trivy reports, unique vulnerability ID counts, govulncheck
reports, build information and SHA-256 checksums as CI artifacts.
The security gate rejects HIGH/CRITICAL Trivy findings or a nonzero govulncheck
exit status. Lower-severity Trivy findings remain visible.

After review and merge, dispatch Downstream release on main with a unique tag
such as v0.11.1-aoksys.1. The release builds locked modules and repeats tests and
scans before publishing. Releases contain separate Helm 3/4 plugin archives;
these are prebuilt and deliberately omit the Helm 3 download hook to avoid
silently installing an upstream binary.

For AMIs, extract the archive matching the installed Helm major and Linux
architecture to the cm-push directory under HELM_PLUGINS (as reported by
helm env). Check the release checksums before extracting and run helm plugin
list and helm cm-push --help afterwards. Do not use the upstream source-install
hook to install these binaries. Helm 4 installation/signature policy must be
validated for the target deployment; do not disable signature verification
globally.

No production release is published automatically by a branch push.
