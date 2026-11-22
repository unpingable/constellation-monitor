#!/usr/bin/env bash
# Build the inactive Python package from a Git worktree: VERSION OUT_DIR.
set -euo pipefail
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
umask 022
[[ $# -eq 2 ]] || { echo "usage: $0 VERSION OUT_DIR" >&2; exit 2; }
version=$1
dpkg --validate-version "$version"
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
source="$root/packaging/host-duty"
[[ $(git -C "$root" rev-parse --show-toplevel) = "$root" ]]
head=$(git -C "$root" rev-parse --verify HEAD)
status=$(git -C "$root" status --porcelain --untracked-files=normal)
worktree_state=clean
if [[ -n $status ]]; then worktree_state=dirty; fi

mkdir -p "$2"
out=$(cd "$2" && pwd -P)
stage=$(mktemp -d "$out/.host-duty-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT
name=constellation-host-duty_${version}_all
d=$stage/$name
lib=$d/usr/lib/constellation-host-duty/host_duty
share=$d/usr/share/constellation-host-duty
doc=$d/usr/share/doc/constellation-host-duty
units=$d/lib/systemd/system

install -d -m 0755 "$d/DEBIAN" "$d/usr/bin" "$lib" "$share" "$doc" "$units"
install -m 0755 "$source/constellation-host-duty" "$source/constellation-host-sample" "$d/usr/bin/"
install -m 0644 "$root"/host_duty/{__init__,core,cli,probe,sample}.py "$lib/"
install -m 0644 "$root"/host_duty/{concerns.toml,probes.example.json} "$source/estate.example.toml" "$share/"
install -m 0644 "$root/host_duty/README.md" "$doc/"
install -m 0644 "$source"/constellation-host-duty.{service,timer} "$units/"
install -m 0755 "$source"/{postinst,prerm,postrm} "$d/DEBIAN/"
cat > "$d/DEBIAN/control" <<EOF
Package: constellation-host-duty
Version: $version
Architecture: all
Maintainer: Constellation operator
Depends: adduser, openssh-client, python3 (>= 3.10)
Section: admin
Priority: optional
Description: Observe conditional availability for explicitly assigned host duty
 Off-host duty ledger and bounded SSH acquisition for the estate collector.
 Includes the one-shot Linux target sampler.
EOF
cat > "$doc/BUILDINFO" <<EOF
package_version=$version
git_head=$head
git_worktree_state=$worktree_state
source_date_epoch=$SOURCE_DATE_EPOCH
build_script_sha256=$(sha256sum "$source/build-deb.sh" | cut -d ' ' -f 1)
EOF
# Hash the copied bytes, including control scripts, for both clean and dirty builds.
(cd "$d" && find DEBIAN lib usr -type f ! -path 'usr/share/doc/constellation-host-duty/SHA256SUMS' -print0 |
    sort -z | xargs -0 sha256sum) > "$doc/SHA256SUMS"
find "$d" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --root-owner-group --build "$d" "$out/$name.deb" >/dev/null
(cd "$out" && sha256sum "$name.deb" > "$name.deb.sha256")
echo "$out/$name.deb"
