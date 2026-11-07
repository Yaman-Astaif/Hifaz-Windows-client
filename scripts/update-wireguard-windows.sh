#!/bin/sh
# Copy the parts of wireguard-windows that Hifaz uses into third_party/.
#
# usage: scripts/update-wireguard-windows.sh TAG
#
# Only two packages are taken: tunnel/winipcfg (addresses, routes, DNS) and
# driver (Go bindings for wireguard.dll, loaded from the application folder).
# The changes made to the upstream files are listed in
# third_party/wireguard-windows/README.md; this script makes exactly those.
set -eu

tag=${1:?usage: $0 TAG (for example v1.1.1)}
repo=https://github.com/WireGuard/wireguard-windows
module=github.com/Yaman-Astaif/Hifaz-Windows-client
dest=third_party/wireguard-windows

cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

git clone -q --depth 1 --branch "$tag" "$repo" "$tmp/src"
commit=$(git -C "$tmp/src" rev-parse HEAD)

rm -rf "$dest/tunnel" "$dest/driver"
mkdir -p "$dest/tunnel/winipcfg" "$dest/driver"
for f in "$tmp"/src/tunnel/winipcfg/*.go; do
	case "$f" in *_test*.go) continue ;; esac
	cp "$f" "$dest/tunnel/winipcfg/"
done
for f in configuration_windows.go driver_windows.go dll_windows.go dll_fromfile_windows.go; do
	cp "$tmp/src/driver/$f" "$dest/driver/"
done
cp "$tmp/src/COPYING" "$dest/COPYING"

# 1. Import winipcfg from its new place.
sed -i "s#golang.zx2c4.com/wireguard/windows/tunnel/winipcfg#$module/$dest/tunnel/winipcfg#" "$dest"/driver/*.go
# 2. Always load wireguard.dll from the application folder (the variant that
#    embeds it in the executable is not copied).
sed -i '1{/^\/\/go:build !load_wgnt_from_rsrc$/d}' "$dest/driver/dll_fromfile_windows.go"
sed -i '1{/^$/d}' "$dest/driver/dll_fromfile_windows.go"
# 3. winipcfg is Windows-only: say so, so the other packages build and test
#    on any system.
for f in "$dest"/tunnel/winipcfg/*.go; do
	case "$f" in *_windows.go) continue ;; esac
	if head -1 "$f" | grep -q '^//go:build'; then
		sed -i '1s#^//go:build \(.*\)$#//go:build windows \&\& (\1)#' "$f"
	else
		sed -i '1i //go:build windows\n' "$f"
	fi
done

sed -i "s#^Source: .*#Source: $repo, tag $tag, commit $commit#" "$dest/README.md"
gofmt -l "$dest" && echo "copied wireguard-windows $tag ($commit)"
