# Monitored page package

Run `packaging/monitored/build-deb.sh VERSION OUT_DIR` from any directory. The
hook builds an architecture-independent Debian package using only the source
reader and documentation; it needs Python 3.10+ at runtime and dpkg-deb to build.
It requires no Rust binary, live configuration, credentials or network access
to build. At install, `nq-ng` supplies the existing `nq` account. The postinst
creates `/var/www/constellation-status` owned by `nq:nq` and reloads systemd
definitions; it activates no timer. The site installer enables the supplied
five-minute timer after reviewing the rendered page. See
[MONITORED.md](../../docs/MONITORED.md) for commands, input contracts, activation,
rollback and the human-session acceptance procedure.

`status-site-monitored-link.patch` is the source handoff for Cartography’s
separate status renderer. Apply it in the Cartography re-cut alongside the
rule `family` labels, receipt release index, incident helper and Grafana config.
