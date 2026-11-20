# Changelog

## 0.2.0

Still needs a Hifaz server 0.8.0 or later; client protocol version 1 is
unchanged. Upgrading over 0.1.x keeps the enrollment.

**Security and administration**
- Elevated uninstall removes machine-wide resources. Device enrollment and
  other local data stay in each Windows profile. To clear that data after
  uninstall, delete `%LOCALAPPDATA%\Hifaz` from your own account.
- Every machine allowlist entry now requires a URL and the server's signing
  fingerprint. Before upgrading, update any URL-only entries under
  `HKLM\SOFTWARE\Policies\Hifaz` with an administrator-verified fingerprint.
  An invalid entry causes the service to refuse all servers.
- The service limits named-pipe connections per Windows account, caps
  unidentified connections, and closes connections that exceed I/O deadlines.
- The service tears down tunnels when the signed session deadline passes,
  including during a control API outage.
- Legacy enrollment links ask you to confirm the server fingerprint before
  the app sends the enrollment token.

**Service**
- Fixed: normal (non-administrator) users could not reach the Hifaz service,
  and the app said the service was not running.
- The app now says why it cannot use the service, with its own message for
  each case: the service is not running; it refused the app (for example
  when the app and the service are different versions); or something other
  than the Hifaz service answered, in which case nothing is sent.

**Enrollment**
- People who used Hifaz before are told which link to ask for: a renewal
  link if the existing device keys were cleared, and a new device link for
  another computer. A renewal
  link greets you with "Welcome back" and the device's name.
- The app checks that the Hifaz service answers before it contacts the
  server, so a service problem no longer uses up the enrollment steps.
- If a step times out, the app goes back to the first screen with the link
  already filled in: press Continue to start again.
- If enrollment is interrupted after two-step verification was set up, the
  app says so, and the next attempt asks for the code. An empty code is
  caught by the app and no longer counts as a failed sign-in.

**Sign-in**
- After a wrong code you can try again on the same screen (up to three
  times, as the server allows) instead of starting over with the password.
- A network error or a busy server no longer ends the code step: press
  Connect again. When the step has timed out, the app says so and asks you
  to sign in again.
- If the tunnel cannot be opened after a correct code, the app signs out on
  the server and goes back to the sign-in screen.

**Networking**
- The app distinguishes waiting for a WireGuard handshake from a working
  connection. DNS switches to the server after the first handshake and
  switches back when connectivity is lost.
- While connected, the server handles all DNS. The app remembers the
  server's control URL address so it can still check the session if DNS
  through the tunnel becomes unavailable.
- The app identifies known WireGuard kill switches and rechecks the link
  when the block clears. Endpoint updates respect split-tunnel routes.

**Window**
- The window stays a fixed size and adjusts when moved between monitors
  with different scaling. Long screens scroll while keeping actions visible.
- Settings and enrollment navigation use clearer Back and Cancel actions.
  The compact connection view includes diagnostics and background notifications.

**Testing**
- The app's protocol client is checked against the Hifaz server code for
  enrollment restarts and the sign-in code step.
- Windows CI builds both installers, checks installation and removal, and
  exercises the installed app's window and screens in Arabic and English.

## 0.1.2 — 2026-11-11

**Window**
- Fixed: the window stayed blank after installation. The page's files
  reached the window empty (a fault in the WebView2 library, worked around),
  and the first screen could be lost when the app was faster than the
  window. Both are fixed and checked on Windows for every build.
- The window has a fixed size: no maximize button, no resizing; it is
  sized for the screen's scaling and always fits on the screen.
- Hifaz now has an icon (a shield), in the window, taskbar, Start menu,
  Settings > Apps and the tray (grey when not connected). The programs carry
  version information.
- Script errors in the window are written to the app's log.

**Testing**
- Every build is installed and started on Windows and its window and screens
  are checked and photographed before it can be published.

## 0.1.1 — 2026-11-11

**Installer**
- Fixed: the installer refused to run on Windows 10 and 11 ("Hifaz needs
  Windows 10 or later"). It now reads the Windows version from the system
  itself.
- Every build is now installed, checked and removed on a Windows machine
  before it can be published.

## 0.1.0 — 2026-11-11

First release. **Needs a Hifaz server 0.8.0 or later** (client protocol
version 1); with an older server the app says so and asks you to have the
server updated. Windows 10 or 11, x64 or ARM64.

**Enrollment**
- Paste the enrollment link from your administrator; the app checks the
  server's identity (fingerprint in the link, or compared by you for older
  links), asks for the password and sets up two-step verification.
- The device makes its own keys; they never leave this computer and are
  sealed for your Windows account.

**Connection**
- Sign in with password and code; the tunnel opens with only the networks
  your group may reach, and names in your organisation's domains resolve
  through Hifaz.
- Configuration changes apply by themselves; when the session ends (sign
  out, idle, time limit, administrator) the tunnel closes and the window
  says why.
- Keys are renewed by themselves when the server asks; the new tunnel keys
  are used from the next sign-in, and a crash during renewal never locks
  the device out.
- Groups that require a device certificate: the app makes its own
  certificate key, gets the certificate at enrollment and renewal, and
  presents it when the server's proxy asks.

**App**
- Arabic and English, right-to-left, light and dark themes, in the style of
  the Hifaz sign-in pages.
- Tray icon with connect, disconnect and quit; starts with Windows (can be
  turned off).
- Works for normal users; installing needs administrator rights once.
- Works next to the WireGuard app and other VPNs; removing Hifaz leaves
  nothing behind.
- Signing in again after a session ended reconnects at once: each sign-in
  gets a new tunnel, with no waiting on old WireGuard session keys.
- The About page shows the version, the developer, the server version the
  app needs, and the third-party components with their licences.

**Known limits**
- The installer is not code-signed yet: Windows SmartScreen warns once
  ("More info" → "Run anyway").
- Proxy auto-configuration (PAC) scripts are not used; a manual proxy set
  in Windows is.

**Administrators**
- Optional machine policy: allowed servers, and whether full tunnels are
  allowed (off by default).
