#!/usr/bin/env bash
# Assemble constellation-attention_VERSION_ARCH.deb from a release binary.
# Usage: packaging/attention/build-deb.sh VERSION ARCH BIN_DIR OUT_DIR
# BIN_DIR holds a release `constellation-attention` built from the same
# source (MONITOR_SOURCE_COMMIT set); see packaging/attention/README.md for
# the hermetic Jammy build. No secrets and no live configuration are packaged.
set -euo pipefail; export LC_ALL=C TZ=UTC; umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P) out_dir=$4
case "$version" in *[!0-9A-Za-z.+:~-]*|'') exit 2;; esac
case "$arch" in amd64|arm64) ;; *) exit 2;; esac
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
bin="$bin_dir/constellation-attention"
[[ -x "$bin" ]] || { echo "missing binary $bin" >&2; exit 2; }
mkdir -p "$out_dir"; stage=$(mktemp -d "$out_dir/.stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
name=constellation-attention_${version}_${arch}
d=$stage/$name
doc=$d/usr/share/doc/constellation-attention
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/lib/systemd/system" "$d/etc/constellation-attention" "$doc"
install -m 0755 "$bin" "$d/usr/bin/"
python3 "$root/packaging/attention/record-build-identity.py" "$d/usr/bin" "$version" "$arch" "$doc/build-identity.json"
install -m 0644 "$root/packaging/attention/constellation-attention.service" "$root/packaging/attention/constellation-attention.timer" "$d/lib/systemd/system/"
# The example only; the live attention.toml is the operator's.
install -m 0644 "$root/packaging/attention/attention.toml.example" "$d/etc/constellation-attention/"
install -m 0644 "$root/docs/ATTENTION.md" "$doc/"
install -m 0644 "$root/packaging/attention/README.md" "$doc/"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$root/packaging/attention/debian/control.in" > "$d/DEBIAN/control"
install -m 0644 "$root/packaging/attention/debian/conffiles" "$d/DEBIAN/conffiles"
for s in postinst postrm; do install -m 0755 "$root/packaging/attention/debian/$s" "$d/DEBIAN/$s"; done
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/$name.deb" >/dev/null
install -m 0644 "$doc/build-identity.json" "$out_dir/$name.build-identity.json"
( cd "$out_dir" && sha256sum "$name.deb" > "$name.deb.sha256" )
echo "built $out_dir/$name.deb"
