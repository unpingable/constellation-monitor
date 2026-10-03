#!/usr/bin/env bash
# Assemble constellation-remediation_VERSION_ARCH.deb from release binaries.
# Usage: packaging/remediation/build-deb.sh VERSION ARCH BIN_DIR OUT_DIR
# BIN_DIR holds release `constellation-remediation-consumer` and
# `constellation-nq-unit-resolver` built from one source export; see
# README.md for the hermetic Jammy build. No configuration, enrollment, keys
# or grants are packaged.
set -euo pipefail; export LC_ALL=C TZ=UTC; umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P) out_dir=$4
case "$version" in *[!0-9A-Za-z.+:~-]*|'') exit 2;; esac
case "$arch" in amd64|arm64) ;; *) exit 2;; esac
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
here=$root/packaging/remediation
consumer=$bin_dir/constellation-remediation-consumer
resolver=$bin_dir/constellation-nq-unit-resolver
for bin in "$consumer" "$resolver"; do
  [[ -x "$bin" ]] || { echo "missing binary $bin" >&2; exit 2; }
done
# The package version starts with the crate version the binaries report.
crate=$("$consumer" --version | awk '{print $2}')
[[ "$version" == "$crate" || "$version" == "$crate"+* ]] || {
  echo "package version $version does not extend the binary version $crate" >&2; exit 2; }
mkdir -p "$out_dir"; stage=$(mktemp -d "$out_dir/.stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
name=constellation-remediation_${version}_${arch}
d=$stage/$name
doc=$d/usr/share/doc/constellation-remediation
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/usr/libexec/constellation-remediation" \
  "$d/lib/systemd/system" "$d/etc/constellation-remediation" "$doc"
install -m 0755 "$consumer" "$resolver" "$d/usr/bin/"
install -m 0755 "$here/nq-ops-as-nq" "$d/usr/libexec/constellation-remediation/"
install -m 0644 "$here/constellation-remediation-consumer.service" \
  "$here/constellation-remediation-consumer.timer" "$d/lib/systemd/system/"
install -m 0644 "$here/consumer.toml.example" "$d/etc/constellation-remediation/"
install -m 0644 "$here/README.md" "$here/model-decider.conf" "$doc/"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$here/debian/control.in" > "$d/DEBIAN/control"
install -m 0644 "$here/debian/conffiles" "$d/DEBIAN/conffiles"
for s in postinst postrm; do install -m 0755 "$here/debian/$s" "$d/DEBIAN/$s"; done
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/$name.deb" >/dev/null
( cd "$out_dir" && sha256sum "$name.deb" > "$name.deb.sha256" )
echo "built $out_dir/$name.deb"
