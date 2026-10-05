#!/usr/bin/env bash
# Assemble constellation-host-posture_VERSION_ARCH.deb from release binaries.
# Usage: packaging/build-deb.sh VERSION ARCH BIN_DIR OUT_DIR
# Optional: QUAL_INPUT_DIR=<dir with hostile-corpus.json and results.json>
#   recorded from the check commands actually run against BIN_DIR's source;
#   installed under /usr/lib/constellation-host-posture/qualification-input/.
set -euo pipefail; export LC_ALL=C TZ=UTC; umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P) out_dir=$4
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
for b in constellation-host-posture constellation-status pulse-nq-load-support; do [[ -x "$bin_dir/$b" ]] || { echo "missing binary $b" >&2; exit 2; }; done
"$bin_dir/constellation-host-posture" --build-info >/dev/null
mkdir -p "$out_dir"; stage=$(mktemp -d "$out_dir/.stage.XXXXXX"); trap 'rm -rf "$stage"' EXIT
d=$stage/constellation-host-posture_${version}_${arch}
install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$d/lib/systemd/system" "$d/usr/share/doc/constellation-host-posture"
install -m 0755 "$bin_dir/constellation-host-posture" "$bin_dir/constellation-status" "$bin_dir/pulse-nq-load-support" "$d/usr/bin/"
# The load-support binary selects its role from its invoked name.
for n in pulse-load-pressure-producer pulse-load-pressure-receiver pulse-support-resolver; do ln -s pulse-nq-load-support "$d/usr/bin/$n"; done
install -m 0644 "$root/docs/nq-host-load-pressure-support-v1.md" "$d/usr/share/doc/constellation-host-posture/"
install -m 0644 "$root/packaging/systemd/constellation-host-posture.service" "$d/lib/systemd/system/"
install -m 0644 "$root/crates/constellation-host-posture/examples/host-posture.toml" "$d/usr/share/doc/constellation-host-posture/host-posture.toml.example"
install -m 0644 "$root/docs/host-posture-runner.md" "$d/usr/share/doc/constellation-host-posture/"
if [[ -n "${QUAL_INPUT_DIR:-}" ]]; then
  for f in hostile-corpus.json results.json; do [[ -f "$QUAL_INPUT_DIR/$f" ]] || { echo "QUAL_INPUT_DIR lacks $f" >&2; exit 2; }; done
  install -d -m 0755 "$d/usr/lib/constellation-host-posture/qualification-input"
  install -m 0644 "$QUAL_INPUT_DIR/hostile-corpus.json" "$QUAL_INPUT_DIR/results.json" "$d/usr/lib/constellation-host-posture/qualification-input/"
  [[ -d "$QUAL_INPUT_DIR/run" ]] && cp -r "$QUAL_INPUT_DIR/run" "$d/usr/lib/constellation-host-posture/qualification-input/run" && chmod -R u=rwX,go=rX "$d/usr/lib/constellation-host-posture/qualification-input/run"
fi
sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$arch/g" "$root/packaging/debian/control.in" > "$d/DEBIAN/control"
for s in postinst prerm postrm; do install -m 0755 "$root/packaging/debian/$s" "$d/DEBIAN/$s"; done
install -m 0644 "$root/LICENSE" "$d/usr/share/doc/constellation-host-posture/copyright"
install -m 0644 "$root/NOTICE" "$d/usr/share/doc/constellation-host-posture/NOTICE"
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/constellation-host-posture_${version}_${arch}.deb" >/dev/null
( cd "$out_dir" && sha256sum "constellation-host-posture_${version}_${arch}.deb" > "constellation-host-posture_${version}_${arch}.deb.sha256" )
echo "built $out_dir/constellation-host-posture_${version}_${arch}.deb"
