#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
[[ $# -eq 4 ]] || { echo 'usage: VERSION ARCH BIN_DIR OUT_DIR' >&2; exit 2; }
version=$1 arch=$2 bins=$(cd "$3" && pwd -P) out=$4
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ -x "$bins/pulse-m2-support" ]]
mkdir -p "$out"
stage=$(mktemp -d "$out/.m2-package.XXXXXX")
trap 'rm -rf "$stage"' EXIT
install -d -m 0755 "$stage/DEBIAN" "$stage/usr/bin" "$stage/usr/share/doc/pulse-m2-support"
install -m 0755 "$bins/pulse-m2-support" "$stage/usr/bin/"
ln -s pulse-m2-support "$stage/usr/bin/pulse-m2-support-resolver"
install -m 0644 "$root/docs/m2-nq-support-v1.md" "$stage/usr/share/doc/pulse-m2-support/"
install -m 0644 "$root/LICENSE" "$stage/usr/share/doc/pulse-m2-support/copyright"
cat > "$stage/DEBIAN/control" <<CONTROL
Package: pulse-m2-support
Version: $version
Architecture: $arch
Section: admin
Priority: optional
Maintainer: Constellation contributors
Depends: libc6 (>= 2.35), nq-ng (>= 0.2.0)
Description: exact local M2 NQ proposition support
 Inert Pulse support tool for the fixed non-production Ubuntu22.04 M2
 systemd/HTTP propositions. Installs no enrollment, custody or service.
CONTROL
find "$stage" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$stage" "$out/pulse-m2-support_${version}_${arch}.deb" >/dev/null
