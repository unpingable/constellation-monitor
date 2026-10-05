# Installed live observation tools

Build with `packaging/live-observation/build-deb.sh VERSION ARCH BIN_DIR OUT_DIR`.
The binary directory must contain the ordinary release
`constellation-nq-boot-unit-resolver` from this source export.

The package installs `/usr/bin/constellation-nq-boot-unit-resolver`,
`/usr/bin/constellation-nq-live-http-reader` and
`/usr/bin/constellation-kubernetes-observation`. The Python tools use the Ubuntu
22.04 Python 3.10 standard library. No source checkout or Python package download
is required. Installation is inert; owner settings and enrollment are separate.

The boot and HTTP readers consume exact admitted NQ custody. They do not collect,
extend freshness, create support or authorize effects. An unavailable native read
remains unavailable. The Kubernetes tool performs bounded GET-only acquisition;
ACQUIRED is not NQ/Pulse standing, aggregate health or a remediation receipt.
No Kubernetes executor is supplied. Token, CA and owner configuration are never
package content. See the installed owner-interface documents for their limits.

This package closes the accepted Workbench reader installation dependency. It
does not change v1/v2 remediation behavior or enable a Workbench action endpoint.
