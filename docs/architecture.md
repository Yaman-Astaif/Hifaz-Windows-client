# Architecture and security model

## Parts and trust

```
 user (no admin)                         system
┌──────────────────────────┐   pipe   ┌──────────────────────────────┐
│ hifaz.exe                │◄────────►│ hifaz-service.exe (SYSTEM)   │
│  window (WebView2), tray │          │  engine: nonces, identities, │
│  keystore (DPAPI)        │          │  policy, one tunnel          │
│  protocol client ────────┼──HTTPS──►│  WireGuardNT (wireguard.dll) │
└──────────────────────────┘  server  └──────────────────────────────┘
```

- The **app** holds the user's keys and talks to the server. It verifies
  every signed document against the server fingerprint pinned at
  enrollment.
- The **service** owns the adapter. It trusts nothing the app says by
  itself: it applies a configuration only from a document signed by the
  server identity *the same Windows user* recorded at enrollment, answering
  a nonce *the service* gave *that user*, and allowed by the machine policy.
- The **server** is identified by its Ed25519 identity key, not by TLS
  alone (TLS usually ends at a reverse proxy).

## What each check stops

| Threat | Stopped by |
|---|---|
| A copied config file used elsewhere | There is none: keys are made on the device and never leave it. Sign-in needs the device key. |
| Certificate groups | A separate ECDSA P-256 key made by the app, sealed with the other keys; the certificate is presented in the TLS handshake to the proxy, which checks it and tells Hifaz. |
| A proxy that ends TLS reads the preshared key | The PSK is sealed to the device's WireGuard key (protocol Appendix A). |
| A fake server behind a valid TLS certificate | Every document is checked against the pinned identity; links carry the fingerprint. |
| Replaying an old server answer to the service | Nonces are issued by the service per Windows user, used once, valid 10 minutes; answers must be fresh. |
| Another Windows user using my device | Keys are sealed with DPAPI for my account; the service records server identities per user SID. |
| Another Windows user taking over or ending my tunnel | The tunnel belongs to the connection that opened it; others get "busy" and see no details. |
| A user creating a fake pipe to steal keys | The app checks the pipe belongs to SYSTEM before sending anything. Users cannot add instances to the real pipe (no FILE_CREATE_PIPE_INSTANCE). The service creates it with FILE_FLAG_FIRST_PIPE_INSTANCE. |
| The service acting as the app's user | The app connects at identification level: the service can see who it is, not act as them. |
| Remote access to the pipe | Remote clients rejected; network logons denied. |
| A server routing all traffic without the administrator's consent | Full tunnels (however split) are refused unless the policy allows them. This covers routes only: while connected, all DNS goes to the server's DNS even when full tunnels are not allowed (see Limits). |
| A dead tunnel leaving the machine without DNS | The app's HTTP client remembers the first address it reached for the server in this sign-in, before the tunnel was up, and connects to it when the name no longer resolves, so it still learns the session has ended; the tunnel then closes and its DNS goes with it. An address learned through Hifaz DNS is never remembered (each sign-in builds a new client). One edge remains: a server name that already resolves, before sign-in, to a local address inside the tunnel's routes. |
| Endpoint resolving inside the tunnel | When the endpoint name changes while connected, the lookup goes to the server's DNS. If the answer is a private, CGNAT, unique-local or link-local address inside the server's narrower routes, it is assumed to be a private answer from the server's DNS, reachable only through the tunnel. The driver does not send the encrypted packets into its own interface, so the tunnel would stop working. The service keeps the current endpoint and logs a line; the next sign-in resolves again. A public address, a literal IP endpoint, or any address when the routes cover its whole family (a full tunnel, however split, as for the full-tunnel policy) is followed. If only the port changes, the service keeps the address without a lookup. |
| Planting files where the service writes | Service data is in `Program Files\Hifaz\Data` (users cannot create anything there beforehand), with a protected ACL; links are refused. |
| Uninstall deleting the wrong folder | Per-user folders that are links are removed as links only. |
| Script injection in the window | The page sets text only, never HTML; strict CSP; no external content; dev tools, context menu and password autosave off. |

Limits, stated plainly:

- DPAPI does not protect against other programs running **as the same
  user**. A TPM-backed key is the later step.
- A local user can enroll with a server of their choosing; the policy's
  server list is how an administrator prevents that.
- Up to 64 connections to the service at once, not per user.
- While connected, every name the machine looks up goes to the server's
  DNS: the server sees all of them and can answer any name with any
  address. This is so for every enrolled server while it is the one
  connected, and even where the policy
  does not allow full tunnels. HTTPS is still protected by certificates
  (a wrong address fails the certificate check); plain HTTP is not. The
  machine policy cannot yet keep the old split DNS (only the server's own
  domains sent to it).
- While Hifaz is connected, another VPN that relies on its adapter's DNS
  without an NRPT rule of its own loses its private names; another VPN's
  more specific NRPT rules still win. This ends when Hifaz disconnects.

## Session lifecycle

1. **Enroll**: paste link → info (fingerprint check) → password (+MFA setup)
   → keys made on the device → `enroll/finish` with a service nonce → the
   service records the identity from the signed answer → keys sealed.
2. **Sign in**: service nonce → `login` (signed by the device key) → OTP if
   asked → signed session document → the service checks it and brings the
   adapter up with the keys the app hands it (wiped from memory on
   disconnect).
3. **Follow**: long-poll `session` with the configuration version in use;
   every answer goes to the service, which applies a newer configuration
   or takes the tunnel down when the session ended.
4. **Renew**: when the server sends `renew_after` and it has passed, new
   WireGuard and device keys (and a new certificate in certificate groups).
   The new WireGuard keys are saved as *pending*; the tunnel keeps the old
   ones, and the next sign-in announces the new key (`wg_public_key`) and
   adopts it. The new device key is used once saved. The server keeps the
   old keys until the new ones are used, so a crash at any point never
   locks the device out.
5. **End**: sign-out, idle, time limit, the administrator, the app
   closing, or the Windows session ending all take the tunnel down, which
   deletes the adapter with its WireGuard session keys. The next sign-in
   always gets a new adapter, so it handshakes with the first packet instead
   of trying the old keys until WireGuard gives up on them (about 10–15
   seconds, as seen with clients that keep the tunnel configured). No
   persistent keepalive: the server detects idle sessions by silence.

## Coexistence

- Own adapter (`Hifaz`, fixed GUID) next to any WireGuard or other VPN
  adapters. The driver skips its own interface when it routes to the
  server, so no extra host route is needed.
- Routes only for `allowed_ips`.
- DNS: when the server sends DNS servers, split and full tunnels alike set
  them on the interface (with the search domains) and add one NRPT rule
  (fixed key) for all names (`.`). So while connected every lookup goes to
  Hifaz DNS, as with the WireGuard app's `DNS =` line: Hifaz DNS can give a
  private answer for a name outside its zone, and in strict DNS mode it is
  the only DNS the user may use. Routes stay split. A DNS server outside
  `allowed_ips` is still applied (its queries leave by the normal network)
  and the service logs it. The rule and interface DNS go when the tunnel
  goes down, and the DNS cache is flushed, so the user's own DNS works again
  at once. If Group Policy sets NRPT rules, Windows ignores local ones; the
  service logs it rather than writing into the policy area.
- No firewall rules, no kill switch, no keepalive (sessions must be able to
  go idle).
- Uninstall removes the adapter, the rule, the driver if no other program
  uses it (the WireGuard app reinstalls it when it needs it), the service
  data and every user's Hifaz folder.
