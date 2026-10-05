#!/usr/bin/env bash
# Ordinary, inert package for the accepted bounded live owner readers.
set -euo pipefail
export LC_ALL=C TZ=UTC
umask 022
[[ $# -eq 4 ]] || { echo "usage: $0 VERSION ARCH BIN_DIR OUT_DIR" >&2; exit 2; }
version=$1 arch=$2 bin_dir=$(cd "$3" && pwd -P) out_dir=$4
case "$version" in *[!0-9A-Za-z.+:~-]*|'') exit 2;; esac
case "$arch" in amd64|arm64) ;; *) exit 2;; esac
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
[[ -x "$bin_dir/constellation-nq-boot-unit-resolver" ]] || exit 2
mkdir -p "$out_dir"
stage=$(mktemp -d "$out_dir/.stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
name=constellation-live-observation_${version}_${arch}
d=$stage/$name
install -d "$d/DEBIAN" "$d/usr/bin" "$d/usr/share/doc/constellation-live-observation" \
  "$d/usr/share/constellation-live-observation/systemd-unit-v3"
install -m 0755 "$bin_dir/constellation-nq-boot-unit-resolver" "$d/usr/bin/"
install -m 0755 "$root/scripts/nq_live_http_read.py" "$d/usr/bin/constellation-nq-live-http-reader"
install -m 0755 "$root/scripts/kubernetes_observation.py" "$d/usr/bin/constellation-kubernetes-observation"
install -m 0644 "$root"/docs/{BOOT_BOUND_UNIT_RELIANCE,nq-current-boot-unit-resolver-v1,nq-live-http-read-v1,kubernetes-published-observation-v1}.md \
  "$root/packaging/live-observation/README.md" "$d/usr/share/doc/constellation-live-observation/"
install -m 0644 "$root/operational-contract/fixtures/systemd-unit-v3/observation-export-vectors.v1.json" \
  "$d/usr/share/constellation-live-observation/systemd-unit-v3/"
cat > "$d/DEBIAN/control" <<EOF
Package: constellation-live-observation
Version: $version
Section: admin
Priority: optional
Architecture: $arch
Maintainer: Constellation contributors
Depends: libc6, python3 (>= 3.10), nq-ng (>= 0.2.5)
Description: Bounded native NQ reliance and GET-only Kubernetes observation
 Installs the boot-bound unit resolver, native HTTP evidence reader and
 optional GET-only Kubernetes acquisition CLI. No service, configuration,
 enrollment, token, executor or effect authority is installed or activated.
EOF
find "$d" -exec touch -h -d "@${SOURCE_DATE_EPOCH:-0}" {} +
dpkg-deb --root-owner-group --build "$d" "$out_dir/$name.deb" >/dev/null
(cd "$out_dir" && sha256sum "$name.deb" > "$name.deb.sha256")
echo "built $out_dir/$name.deb"
