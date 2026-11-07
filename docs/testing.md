# Testing

## Automated

| Where | What |
|---|---|
| `make check` (any system) | Protocol against the shared vectors (`internal/protocol/testdata/vectors.json`, a copy of `docs/client-protocol-vectors.json` in the Hifaz repository; keep them identical). End-to-end app flows against `internal/fakeserver` and the real service engine: enrollment with MFA, sign-in with OTP, configuration changes, server-ended sessions, disconnect, quit, key renewal, refused full tunnel, wrong fingerprint, app too old. Engine checks: nonces, replay, other users, policy, refused documents. |
| CI, Windows job | The named pipe (overlapped I/O, client identity, owner check, first-instance), DPAPI, and a real WireGuardNT adapter: up, routes, NRPT rule, reconfigure, down, nothing left. Builds a test MSI. |

## Against a Hifaz server (test environment)

Needs Hifaz 0.8.0 (built from `feature/0.8.0`) in a test environment, and a
Windows 10 or 11 VM (x64; arm64 if available) with the test MSI from CI.

Server preparation: a user with MFA, a user without MFA, a group with
`allowed_ips` for the test network and DNS with a search domain, a group
with `0.0.0.0/0`, a group that requires device certificates.

### Checklist

Install and basics
- [ ] Install as admin; then sign in to Windows as a **normal user** for everything below.
- [ ] The service runs (`sc query Hifaz`); the app starts from the Start menu and at sign-in (tray only).
- [ ] Window: Arabic by default, right-to-left; English switch; light/dark; About shows Yaman Astaif and the version.

Enrollment
- [ ] Link with fingerprint: enrolls; MFA setup with the QR code; device name when the admin left it empty.
- [ ] Link without fingerprint (made before 0.8.0): the fingerprint screen; "differs" cancels.
- [ ] Used or expired link: clear message. MFA-only or certificate link: "opens in the browser".
- [ ] The device card on the dashboard shows method `app`, platform, app version, OS.

Sign-in and session
- [ ] Sign in with password, then OTP. Tunnel up; only the group's ranges routed (`route print`); names in the search domain resolve through Hifaz DNS (`Resolve-DnsName`), other names unchanged.
- [ ] Change the group's ranges on the dashboard: applied within seconds, no reconnect.
- [ ] Idle timeout, time limit, admin ends the session, admin disables the device: the tunnel closes and the window says why.
- [ ] Disconnect from the window and from the tray; quit from the tray: the session ends on the server too.
- [ ] Clock 10 minutes off: clear message with the server time.
- [ ] `min_app_version` above the app's version: "update needed", with the download link if set.
- [ ] Full-tunnel group: refused by default; allowed with `AllowFullTunnel=1`.
- [ ] `Servers` policy without the test server: enrollment and sign-in refused.

Keys
- [ ] Set `renew_after` in the past (or ask for new keys): renewed while connected; next sign-in works with the new keys.
- [ ] Offline past `keys_expire_at`: "keys expired"; a renewal link fixes it.

Several users
- [ ] Two Windows users on one machine (fast user switching): the second sees "in use by another user"; cannot disconnect the first; each has their own enrollment.
- [ ] Signing out of Windows ends that user's tunnel.

Coexistence
- [ ] Official WireGuard app installed with its own tunnel up at the same time: both work; uninstalling Hifaz leaves the WireGuard app working.
- [ ] Another VPN (OpenVPN or the system VPN): both work.
- [ ] Sleep and wake, Wi-Fi change: the session continues or ends cleanly.
- [ ] Proxy set in Windows settings: the app reaches the server through it.

Uninstall
- [ ] Uninstall: no `Hifaz` adapter, no NRPT rule under `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`, no `Program Files\Hifaz`, no `%LOCALAPPDATA%\Hifaz` for any user, no start-up entry.
- [ ] Upgrade (install a newer MSI over an older one): keeps the enrollment.
