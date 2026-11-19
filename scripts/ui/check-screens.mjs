// UI test, every screen at the window's fixed size: each screen the app can
// show, filled as the app fills it (window.hifaz.onView, onPrefs and
// showPage only), at 460x680 page pixels, in Arabic and English, light and
// dark. Each one either fits, or scrolls inside main with its buttons fully
// visible and not covered, stuck to the bottom with no gap; the header never
// moves; an error is in view as the screen first shows. A second pass runs
// at 460x657 (a 1080p screen at 150%: the window clamped to the work area).
// Writes a screenshot of each to the folder given as the first argument.
// Runs after check-start.mjs on the same page.
//
//   node scripts/ui/check-screens.mjs <out-dir> [port]
import { connect, waitFor } from "./cdp.mjs";

const out = process.argv[2] || ".";
const port = Number(process.argv[3] || 9222);
const W = 460, H = 680; // the window's client area at 100% (internal/winui/geometry.go)
const CLAMPED = 657; // 1920x1080 at 150%: a 1008-pixel work area, less the frame, at 1.5
const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? "ok" : "FAILED"}: ${what}`);
  if (!ok) failures.push(what);
};

const at = (min) => new Date(Date.now() + min * 60000).toISOString();
const account = { server: "https://vpn.example.com", username: "first.last", device: "Work laptop",
  fingerprint: "3F2A 9C41 7D0E B6A8", keys_expire_at: at(60 * 24 * 300) };
const enroll = { server: "https://vpn.example.com", username: "first.last", kind: "device",
  fingerprint: "3f2a9c417d0eb6a85c1e4f7a2b9d0c6e8a1f3b5d7c9e0a2b4d6f8a1c3e5b7d9f" };
const routes = ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16", "10.40.0.0/16", "172.16.0.0/20",
  "172.16.32.0/20", "172.16.64.0/20", "192.168.10.0/24", "192.168.20.0/24", "192.168.30.0/24",
  "192.168.40.0/24", "fd00:10::/64"];

// Each case: a name, the view, and the window page ("" for the app's screens).
const cases = [
  ["setup", { screen: "setup" }],
  ["setup-replacing", { screen: "setup", replacing: true, account, error: { code: "invalid_link" } }],
  ["fingerprint", { screen: "enroll_fingerprint", enroll }],
  ["enroll-password", { screen: "enroll_password", error: { code: "invalid_credentials" },
    enroll: { ...enroll, device: "Work laptop", name_editable: true, code_required: true } }],
  ["enroll-mfa", { screen: "enroll_mfa", error: { code: "invalid_code" },
    enroll: { ...enroll, mfa_secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
      mfa_uri: "otpauth://totp/Hifaz:first.last?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Hifaz" } }],
  ["enroll-mfa-ok", { screen: "enroll_mfa", enroll: { ...enroll, mfa_secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    mfa_uri: "otpauth://totp/Hifaz:first.last?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Hifaz" } }],
  ["signin", { screen: "signin", account, error: { code: "invalid_credentials" } }],
  ["signin-otp", { screen: "signin_otp", account, error: { code: "invalid_code" } }],
  ["connected", { screen: "connected", account, session: { address: "10.98.0.17", connected_at: at(-42),
    expires_at: at(8 * 60), idle_timeout_seconds: 900, allowed_ips: routes, rx_bytes: 48213504, tx_bytes: 3145728 } }],
  ["update-required", { screen: "update_required", account,
    update: { min_version: "9.0.0", download_url: "https://example.com/hifaz.msi" } }],
  ["settings", { screen: "signin", account }, "settings"],
  ["about", { screen: "signin", account }, "about"],
];

// show draws a case as the app would (from another screen, so the page
// treats it as new) and waits two frames, so layout, fonts and the
// scroll-driven edge of the button bar are up to date. It reports where the
// page put itself (the error must be in view), then scrolls back to the top
// for the checks.
const show = (view, page, prefs) => cdp.evaluate(`(async () => {
  window.hifaz.onPrefs(${JSON.stringify(prefs)});
  window.hifaz.showPage("");
  window.hifaz.onView({ screen: "loading" });
  window.hifaz.onView(${JSON.stringify(view)});
  window.hifaz.showPage(${JSON.stringify(page || "")});
  await document.fonts.ready;
  await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  const main = document.querySelector("main");
  const m = main.getBoundingClientRect();
  const e = document.getElementById("error");
  const bar = [...document.querySelectorAll("section:not([hidden]) .actions")][0];
  const limit = bar ? bar.getBoundingClientRect().top : m.bottom;
  const r = e.getBoundingClientRect();
  const first = { scrollTop: Math.round(main.scrollTop),
    error: e.hidden ? null : r.top >= m.top - 1 && r.bottom <= limit + 1 };
  main.scrollTop = 0;
  await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  return first;
})()`);

const frames = `new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)))`;

// measure reports the layout of the screen that is shown.
const measure = () => cdp.evaluate(`(() => {
  const main = document.querySelector("main");
  const shown = [...document.querySelectorAll("section[data-screen], section[data-page]")].filter((s) => !s.hidden);
  const s = shown[0];
  const m = main.getBoundingClientRect();
  const bar = s && s.querySelector(".actions");
  const buttons = bar ? [...bar.querySelectorAll(".btn")].filter((b) => !b.hidden) : [];
  const card = s && s.querySelector(".card");
  const c = card ? card.getBoundingClientRect() : null;
  const doc = document.scrollingElement;
  return {
    sections: shown.length,
    screen: s ? (s.dataset.screen || s.dataset.page) : null,
    docScroll: doc.scrollHeight - innerHeight, docScrollX: doc.scrollWidth - innerWidth,
    mainScrollX: main.scrollWidth - main.clientWidth,
    fits: main.scrollHeight <= main.clientHeight,
    content: main.scrollHeight, room: main.clientHeight,
    bar: !!bar, barHeight: bar ? Math.round(bar.getBoundingClientRect().height) : 0,
    barGap: bar ? Math.round(m.bottom - bar.getBoundingClientRect().bottom) : null,
    edge: bar ? getComputedStyle(bar).borderTopColor : "",
    buttons: buttons.map((b) => {
      const r = b.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      return { text: b.textContent, inside: r.top >= m.top - 0.5 && r.bottom <= m.bottom + 0.5 &&
        r.left >= m.left - 0.5 && r.right <= m.right + 0.5, hit: !!hit && (hit === b || b.contains(hit)) };
    }),
    gaps: c ? [Math.round(c.left * 10) / 10, Math.round((innerWidth - c.right) * 10) / 10] : null,
    direction: getComputedStyle(main).direction,
  };
})()`);

const cdp = await connect(port);
try {
  await waitFor(cdp, "document.readyState === 'complete' && typeof window.hifaz === 'object'", "the page");
  const real = await cdp.evaluate(`({ w: innerWidth, h: innerHeight, dpr: devicePixelRatio })`);
  console.log(`window page size before the override: ${real.w}x${real.h} at ${real.dpr}x`);
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });
  const size = await cdp.evaluate(`({ w: innerWidth, h: innerHeight })`);
  check(size.w === W && size.h === H, `page is ${W}x${H} (got ${size.w}x${size.h})`);

  let n = 10;
  for (const [name, view, page] of cases) {
    for (const lang of ["ar", "en"]) {
      for (const theme of ["light", "dark"]) {
        const what = `${name}, ${lang}, ${theme}`;
        const first = await show(view, page, { lang, theme });
        const f = await measure();
        console.log(`${what}: first shown ${JSON.stringify(first)}; ${JSON.stringify(f)}`);
        if (first.error !== null) check(first.error, `${what}: the error is in view as the screen shows (scrollTop ${first.scrollTop})`);
        if (!f.fits) check(Math.abs(f.barGap) <= 1, `${what}: the stuck button bar is at the bottom, no gap (${f.barGap}px)`);
        await cdp.screenshot(`${out}/${n}-${name}-${lang}-${theme}.png`);
        check(f.sections === 1 && f.screen === (page || view.screen), `${what}: the screen is shown`);
        check(f.docScroll <= 0 && f.docScrollX <= 0 && f.mainScrollX <= 0, `${what}: the page itself does not scroll, no horizontal scrolling`);
        check(f.bar && f.buttons.length > 0, `${what}: the buttons are in a button bar`);
        check(f.fits || f.buttons.every((b) => b.inside && b.hit),
          `${what}: fits (${f.content}/${f.room}px) or its buttons are visible and not covered`);
        check(!!f.gaps && Math.abs(f.gaps[0] - f.gaps[1]) <= 1, `${what}: even side margins (${f.gaps})`);
        if (lang === "ar") check(f.direction === "rtl", `${what}: the scrolling area is right to left`);

        // Scrolled to the end: the header stays at the top, the buttons
        // still show.
        const end = await cdp.evaluate(`(async () => {
          const main = document.querySelector("main");
          main.scrollTop = main.scrollHeight;
          await ${frames};
          const bar = [...document.querySelectorAll("section:not([hidden]) .actions")][0];
          return { top: document.querySelector("header.top").getBoundingClientRect().top,
            scrolled: main.scrollTop, edge: bar ? getComputedStyle(bar).borderTopColor : "" };
        })()`);
        check(end.top === 0, `${what}: the header stays at the top when scrolled (${end.top}px)`);
        if (!f.fits) {
          console.log(`  bar edge while content is under it: ${f.edge}; at the end: ${end.edge}`);
          if (lang === "en" && theme === "light") await cdp.screenshot(`${out}/${n}-${name}-${lang}-${theme}-end.png`);
        }
      }
    }
    n++;
  }

  // The window clamped to a shorter work area: still fits, or scrolls with
  // its buttons visible.
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: W, height: CLAMPED, deviceScaleFactor: 1, mobile: false });
  n = 40;
  for (const [name, view, page] of cases) {
    for (const lang of ["ar", "en"]) {
      const what = `${name}, ${lang}, ${CLAMPED}px`;
      const first = await show(view, page, { lang, theme: "light" });
      const f = await measure();
      console.log(`${what}: first shown ${JSON.stringify(first)}; ${JSON.stringify(f)}`);
      await cdp.screenshot(`${out}/${n}-${name}-${lang}-${CLAMPED}.png`);
      check(f.docScroll <= 0 && f.docScrollX <= 0 && f.mainScrollX <= 0, `${what}: the page itself does not scroll`);
      check(f.fits || f.buttons.every((b) => b.inside && b.hit),
        `${what}: fits (${f.content}/${f.room}px) or its buttons are visible and not covered`);
      if (!f.fits) check(Math.abs(f.barGap) <= 1, `${what}: the stuck button bar is at the bottom, no gap (${f.barGap}px)`);
      if (first.error !== null) check(first.error, `${what}: the error is in view as the screen shows`);
    }
    n++;
  }
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });

  // Long enrollment screen: a focused field is not hidden under the bar.
  for (const lang of ["ar", "en"]) {
    await show(cases[3][1], "", { lang, theme: "light" });
    const f = await cdp.evaluate(`(async () => {
      const main = document.querySelector("main");
      main.scrollTop = 0;
      await ${frames};
      const name = document.getElementById("e-name");
      name.focus();
      await ${frames};
      const bar = document.querySelector('section[data-screen="enroll_password"] .actions');
      return { focused: document.activeElement === name, field: Math.ceil(name.getBoundingClientRect().bottom),
        bar: Math.floor(bar.getBoundingClientRect().top), fits: main.scrollHeight <= main.clientHeight };
    })()`);
    console.log(`focus, ${lang}: ${JSON.stringify(f)}`);
    await cdp.screenshot(`${out}/30-enroll-password-focus-${lang}.png`);
    check(f.focused && f.field <= f.bar, `device name field, ${lang}: focused and above the button bar (field ends ${f.field}px, bar at ${f.bar}px)`);
  }

  // Two-step setup scrolled to the end: a new error is scrolled into view.
  for (const lang of ["ar", "en"]) {
    const mfa = { ...cases[4][1], error: undefined };
    await show(mfa, "", { lang, theme: "light" });
    await cdp.evaluate(`(async () => { const m = document.querySelector("main"); m.scrollTop = m.scrollHeight; await ${frames}; return true; })()`);
    const f = await cdp.evaluate(`(async () => {
      window.hifaz.onView(${JSON.stringify(cases[4][1])});
      await ${frames};
      const m = document.querySelector("main").getBoundingClientRect();
      const e = document.getElementById("error");
      const r = e.getBoundingClientRect();
      return { shown: !e.hidden, top: Math.round(r.top), bottom: Math.round(r.bottom), mainTop: Math.round(m.top), mainBottom: Math.round(m.bottom) };
    })()`);
    console.log(`error, ${lang}: ${JSON.stringify(f)}`);
    await cdp.screenshot(`${out}/31-enroll-mfa-error-${lang}.png`);
    check(f.shown && f.top >= f.mainTop && f.bottom <= f.mainBottom, `two-step setup, ${lang}: a new error is scrolled into view`);
  }

  for (const lang of ["ar", "en"]) {
    await show(cases[8][1], "", { lang, theme: "light" });
    const navigation = await cdp.evaluate(`(() => {
      const settings = document.getElementById("b-settings");
      const about = document.querySelector('[data-page-go="about"]');
      const done = document.querySelector('[data-page-go=""]');
      const connected = document.querySelector('[data-screen="connected"]');
      settings.focus();
      settings.click();
      const opened = settings.getAttribute("aria-expanded") === "true" &&
        document.activeElement === document.querySelector('#settings-page h1');
      about.click();
      const aboutShown = !document.querySelector('[data-page="about"]').hidden;
      document.querySelector('[data-page-go="settings"]').click();
      const aboutFocusRestored = document.activeElement === about;
      done.click();
      return { opened, aboutShown, aboutFocusRestored, returned: !connected.hidden &&
        settings.getAttribute("aria-expanded") === "false" && document.activeElement === settings };
    })()`);
    check(Object.values(navigation).every(Boolean), `connected → Settings → About → Settings → connected, ${lang}`);
  }

  for (const lang of ["ar", "en"]) {
    const connected = cases[8][1];
    await show({ ...connected, service_status: "diagnosticsServiceRunning",
      session: { ...connected.session, dns_active: true, dns_servers: ["192.0.2.53"] } }, "", { lang, theme: "light" });
    const result = await cdp.evaluate(`(() => {
      const section = document.querySelector('[data-screen="connected"]');
      const primary = section.querySelector('[data-act="disconnect"]');
      const link = section.querySelector('.actions [data-page-go="diagnostics"]');
      const primaryFirst = primary.nextElementSibling === link;
      link.click();
      const diagnostics = document.querySelector('[data-page="diagnostics"]');
      const summary = document.querySelector('#support-summary pre').textContent;
      const open = !diagnostics.hidden && section.hidden;
      const redacted = summary.length > 0 && !/vpn\\.example\\.com|first\\.last|10\\.98\\.0\\.17|192\\.0\\.2\\.53/.test(summary);
      document.getElementById('diagnostics-back').click();
      return { primaryFirst, open, redacted, returned: !section.hidden };
    })()`);
    check(Object.values(result).every(Boolean), `Diagnostics opens, redacts details, and returns, ${lang}`);
  }

  // Back to the first screen, as the app left it.
  await cdp.send("Emulation.clearDeviceMetricsOverride");
  await show({ screen: "setup" }, "", { lang: "ar", theme: "light" });
} finally {
  cdp.close();
}
if (failures.length) {
  console.log(`${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("UI screen checks passed.");
