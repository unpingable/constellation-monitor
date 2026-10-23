# Monitored page package

Run `packaging/monitored/build-deb.sh VERSION OUT_DIR` from any directory. The
hook builds an architecture-independent Debian package using only the source
reader and documentation; it needs Python 3.10+ at runtime and dpkg-deb to build.
It requires no Rust binary, live configuration, credentials or network access.
The package installs no maintainer scripts and activates no timer. The site
installer creates the existing status-site directory and enables the supplied
five-minute timer after reviewing the rendered page. See
[MONITORED.md](../../docs/MONITORED.md) for commands, input contracts, activation,
rollback and the human-session acceptance procedure.
