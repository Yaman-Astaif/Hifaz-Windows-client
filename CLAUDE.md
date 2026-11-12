# Hifaz for Windows - حِفاظ

The Windows app for the Hifaz WireGuard sign-in gateway (`../Hifaz`): enroll the
computer, sign in (password + MFA), the tunnel opens; sign out, idle or time
limit, it closes. Speaks client protocol v1 (`../Hifaz/docs/client-protocol.md`).
Owner: Yaman Astaif. Full description: `README.md`; security model: `docs/architecture.md`.

## Two programs
- `hifaz.exe` (`cmd/hifaz`): the app, runs as the user with **no admin rights**. Window
  (WebView2) and tray; holds device keys (DPAPI, current user); talks to the server.
- `hifaz-service.exe` (`cmd/hifaz-service`): LocalSystem, the only part that touches the
  network (one WireGuardNT adapter, routes, DNS). Applies only what the server signed for the calling user.
- They talk over a local named pipe (`internal/ipc`). Platform-independent logic lives in files
  without `_windows`, so most code is tested on any system.

## Commands
- `make check`: gofmt, vet (Linux, Windows x64 and arm64), tests with `-race`, cross-builds. Must pass before pushing.
- `scripts/interop-hifaz.sh ../Hifaz`: the protocol client against the real server code.
- MSI, real adapter, install and UI tests run on Windows in CI (`docs/testing.md`); `scripts/build.ps1` builds the MSI.

## Rules from the owner
- The project will be public: no built-in servers, names, domains or company settings.
- Everything works for normal users; only installing may need admin once.
- Never disturb anything else on the machine: other VPNs, adapters, services; nothing left after uninstall.
- Arabic and English, right-to-left done properly, light and dark, same style as the Hifaz pages.
  The About page shows the developer, **Yaman Astaif**, and the version. The logo slot stays empty.
- Protocol changes are agreed in `../Hifaz/docs/client-protocol.md` first. `internal/protocol/testdata/vectors.json`
  must stay identical to `../Hifaz/docs/client-protocol-vectors.json`. Use the `protocol-keeper` agent.
- Releases are tagged `vX.Y.Z` and published by the owner; the workflow fills the notes from `CHANGELOG.md`.
- Releases, tags and merges are done by the owner only.

## How agents work here
- Work only on `agent/<issue>-<name>` branches, then open a pull request. Never commit or push to `main`.
- One issue at a time: `/work-issue <number>` runs planner → implementer → reviewer
  (→ protocol-keeper) → pull request, and writes `docs/agent-log/<date>-issue-<n>.md`.
- New ideas become issues first (planner, or the Matt Pocock skills `/grill-with-docs`,
  `/to-spec`, `/to-tickets`); they are built only after the owner asks for them.
- Changes to `installer/`, `.github/` and `third_party/` ask the owner first.
- Every action is logged by hooks to `.claude/logs/` (not committed). Do not edit
  `.claude/settings.json` or `.claude/hooks/`; the owner changes those.

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues on this repo, using the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `GLOSSARY.md` and `docs/adr/` at the repo root, created when needed. See `docs/agents/domain.md`.
