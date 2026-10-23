#!/usr/bin/env bash
# Build the stdlib-only reader package: VERSION OUT_DIR. No services are started.
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
[[ $# -eq 2 ]] || { echo "usage: $0 VERSION OUT_DIR" >&2; exit 2; }
version=$1
case "$version" in *[!0-9A-Za-z.+:~-]*|'') exit 2;; esac
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
mkdir -p "$2"
out=$(cd "$2" && pwd -P)
stage=$(mktemp -d "$out/.monitored-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
name=constellation-monitored_${version}_all
d=$stage/$name
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/usr/lib/constellation-monitored" "$d/lib/systemd/system" "$d/usr/share/doc/constellation-monitored" "$d/var/www/constellation-status"
install -m 0755 "$root/packaging/monitored/constellation-monitored" "$d/usr/bin/constellation-monitored"
install -m 0644 "$root/monitored/constellation-monitored.py" "$root/monitored/toml_subset.py" "$d/usr/lib/constellation-monitored/"
install -m 0644 "$root/packaging/monitored/constellation-monitored.service" "$root/packaging/monitored/constellation-monitored.timer" "$d/lib/systemd/system/"
install -m 0644 "$root/docs/MONITORED.md" "$d/usr/share/doc/constellation-monitored/"
cat > "$d/DEBIAN/control" <<EOF
Package: constellation-monitored
Version: $version
Architecture: all
Maintainer: Constellation operator
Depends: python3 (>= 3.10), nq-ng (>= 0.2.0)
Section: admin
Priority: optional
Description: Explain host monitoring and coverage from local declarations
 Read-only terminal and static HTML inventory. Missing evidence remains unknown.
EOF
install -m 0755 "$root/packaging/monitored/postinst" "$d/DEBIAN/postinst"
# Installation deliberately leaves activation and site exposure to the site installer.
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out/$name.deb" >/dev/null
(cd "$out" && sha256sum "$name.deb" > "$name.deb.sha256")
echo "$out/$name.deb"
