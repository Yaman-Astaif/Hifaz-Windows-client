# WireGuardNT

`wireguard.dll` (with the WireGuardNT driver inside, signed by Microsoft) is
downloaded at build time by `scripts/fetch-wireguard-nt.ps1` from
https://download.wireguard.com/wireguard-nt/ and shipped **unmodified** next
to `hifaz-service.exe`. It is not kept in this repository.

Licence: the "Prebuilt Binaries License" of WireGuard LLC (`LICENSE.txt` in
the zip, installed as `licenses\wireguard-nt-LICENSE.txt`). It allows
shipping the DLL unmodified alongside software that uses it only through
the API in `wireguard.h`, which is what Hifaz does (through
`third_party/wireguard-windows/driver`). It does not allow using the
WireGuard name to promote Hifaz.

Pinned version: 1.1. The zip's SHA-256 goes in `SHA256`; every build also
checks the DLLs' Authenticode signature by WireGuard LLC.
