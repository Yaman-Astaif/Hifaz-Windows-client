# wireguard-windows (copied parts)

Source: https://github.com/WireGuard/wireguard-windows, tag v1.1.1, commit f0605c3e3dcc5ff801e19158fd6255378b99e17c

Licence: MIT, see `COPYING`. Copyright (C) WireGuard LLC.

Two packages are copied, unchanged except for the three points below:

| Package | Use in Hifaz |
|---|---|
| `tunnel/winipcfg` | Addresses, routes, DNS and interface settings of the tunnel adapter. |
| `driver` | Go bindings for `wireguard.dll` (the API in `wireguard.h`). |

Changes made to the upstream files:

1. `driver` imports `winipcfg` from this folder.
2. `driver` always loads `wireguard.dll` from the application folder
   (`dll_fromfile_windows.go`, with its build constraint removed). The
   upstream variant that embeds the DLL inside the executable is not copied:
   Hifaz ships `wireguard.dll` unmodified, next to the program, as its
   licence asks.
3. `winipcfg` files get a `windows` build constraint, so the rest of the
   repository builds and tests on any system.

The module itself is not imported because it needs a newer Go than the rest
of the project wants to require, and it pulls in a GUI toolkit Hifaz does not
use. To take a newer release run `scripts/update-wireguard-windows.sh TAG`,
review the diff, and update the tag and commit above (the script does).
