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

The package also installs the read-only `constellation-diagnostic` command and
its canonical guide at `/usr/share/doc/constellation-monitored/DIAGNOSTIC.md`.
It adds no diagnostic service or activation. Exit 0 records a completed
investigation, including unknown findings; it does not establish host health.

`status-site-monitored-link.patch` is the source handoff for Cartography’s
separate status renderer. Apply it in the Cartography re-cut alongside the
rule `family` labels, receipt release index, incident helper and Grafana config.
