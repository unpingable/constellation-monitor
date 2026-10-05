#!/usr/bin/env bash
# Assemble constellation-attention_VERSION_ARCH.deb from a release binary.
# Usage: packaging/attention/build-deb.sh VERSION ARCH BIN_DIR OUT_DIR
# BIN_DIR holds a release `constellation-attention` built from the same
# source (MONITOR_SOURCE_COMMIT set); see packaging/attention/README.md for
# the hermetic Jammy build. No secrets and no live configuration are packaged.
set -euo pipefail; export LC_ALL=C TZ=UTC; umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P) out_dir=$4
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
bin="$bin_dir/constellation-attention"
[[ -x "$bin" ]] || { echo "missing binary $bin" >&2; exit 2; }
info=$("$bin" --build-info)
crate=$("$bin" --version | awk '{print $2}')
[[ "$version" == "$crate" || "$version" == "$crate"+* ]] || {
  echo "package version $version does not extend binary version $crate" >&2; exit 2; }
grep -q '"minimum_nq":"0.2.2"' <<<"$info" || { echo "binary does not name minimum_nq 0.2.2: $info" >&2; exit 2; }
if grep -q '"source_commit":"unavailable"' <<<"$info"; then
  echo "binary has no source commit; build with MONITOR_SOURCE_COMMIT set" >&2; exit 2
fi
mkdir -p "$out_dir"; stage=$(mktemp -d "$out_dir/.stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
name=constellation-attention_${version}_${arch}
d=$stage/$name
doc=$d/usr/share/doc/constellation-attention
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/lib/systemd/system" "$d/etc/constellation-attention" "$doc"
install -m 0755 "$bin" "$d/usr/bin/"
install -m 0644 "$root/packaging/attention/constellation-attention.service" "$root/packaging/attention/constellation-attention.timer" "$d/lib/systemd/system/"
# The example only; the live attention.toml is the operator's.
install -m 0644 "$root/packaging/attention/attention.toml.example" "$d/etc/constellation-attention/"
install -m 0644 "$root/docs/ATTENTION.md" "$doc/"
install -m 0644 "$root/packaging/attention/OPERATOR.md" "$doc/README.md"
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$root/packaging/attention/debian/control.in" > "$d/DEBIAN/control"
install -m 0644 "$root/packaging/attention/debian/conffiles" "$d/DEBIAN/conffiles"
for s in postinst postrm; do install -m 0755 "$root/packaging/attention/debian/$s" "$d/DEBIAN/$s"; done
install -m 0644 "$root/LICENSE" "$doc/copyright"
install -m 0644 "$root/NOTICE" "$doc/NOTICE"
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/$name.deb" >/dev/null
( cd "$out_dir" && sha256sum "$name.deb" > "$name.deb.sha256" )
echo "built $out_dir/$name.deb"
