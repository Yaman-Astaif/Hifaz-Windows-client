#!/bin/sh
# Runs the app's protocol client and service engine against the real Hifaz
# server, inside a Hifaz checkout, without changing it:
#
#   scripts/interop-hifaz.sh /path/to/Hifaz     (a checkout of feature/0.8.0 or later)
#
# It copies internal/{protocol,daemon,ipc,policy} (without Windows files and
# tests) and scripts/interop/winclient_interop_test.go.in into the checkout,
# runs the test with the race detector, and removes what it copied.
set -eu

hifaz=${1:?usage: $0 /path/to/Hifaz}
here=$(cd "$(dirname "$0")/.." && pwd)
dest="$hifaz/internal/winclient"
test="$hifaz/internal/api/winclient_interop_test.go"

[ -e "$dest" ] || [ -e "$test" ] && { echo "$dest or $test already exists; not touching it" >&2; exit 1; }
trap 'rm -rf "$dest" "$test"' EXIT

for p in protocol daemon ipc policy; do
	mkdir -p "$dest/$p"
	for f in "$here/internal/$p"/*.go; do
		case "$f" in *_test.go|*_windows.go) continue ;; esac
		sed 's#github.com/Yaman-Astaif/Hifaz-Windows-client/internal/#hifaz/internal/winclient/#' "$f" > "$dest/$p/$(basename "$f")"
	done
done
cp "$here/scripts/interop/winclient_interop_test.go.in" "$test"
cd "$hifaz"
go test -count=1 -race -run 'TestWinClient' -v ./internal/api/
