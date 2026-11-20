// UI test, first start: the installed app shows its first screen, styled,
// in Arabic and right to left; English and the dark theme work; an error,
// Settings and About show. Writes screenshots to the folder given as the
// first argument.
//
//   node scripts/ui/check-start.mjs <out-dir> [port]
import { connect, waitFor } from "./cdp.mjs";

const out = process.argv[2] || ".";
const port = Number(process.argv[3] || 9222);
const failures = [];
const check = (ok, what) => {
  console.log(`${ok ? "ok" : "FAILED"}: ${what}`);
  if (!ok) failures.push(what);
};

const cdp = await connect(port);
try {
  console.log(`page: ${cdp.page.url}`);
  await waitFor(cdp, "document.readyState === 'complete'", "the page to load");
  const state = () => cdp.evaluate(`(() => {
    const shown = [...document.querySelectorAll("section[data-screen]")].find((s) => !s.hidden);
    const body = getComputedStyle(document.body);
    return {
      href: location.href,
      screen: shown ? shown.dataset.screen : null,
      title: shown ? (shown.querySelector("h1") || {}).textContent : null,
      dir: document.documentElement.dir,
      lang: document.documentElement.lang,
      background: body.backgroundColor,
      font: body.fontFamily,
      fontsLoaded: document.fonts.status,
      bridge: !!(window.chrome && window.chrome.webview),
      app: typeof window.hifaz,
    };
  })()`);
  let s = await waitFor(cdp, `(() => { const x = [...document.querySelectorAll("section[data-screen]")].find((s) => !s.hidden); return x && x.dataset.screen !== "loading" && x.dataset.screen; })()`, "the first screen", 30000)
    .then(state, async (e) => { console.log(JSON.stringify(await state())); throw e; });
  console.log(JSON.stringify(s));
  await cdp.screenshot(`${out}/01-start-ar.png`);
  check(s.href === "https://hifaz.invalid/index.html", "page served from the app");
  check(s.bridge && s.app === "object", "page script and app bridge running");
  check(s.screen === "setup", `first screen is setup (got ${s.screen})`);
  check(s.dir === "rtl" && s.lang === "ar", "Arabic, right to left, by default");
  check(s.background === "rgb(246, 245, 239)", `stylesheet applied (background ${s.background})`);
  check(!!s.title && s.title.trim().length > 0, `heading shown (${s.title})`);
  await cdp.evaluate("document.fonts.ready.then(() => true)");
  check(await cdp.evaluate(`document.fonts.check('700 22px "WG Heading"', "حفاظ")`), "Arabic heading font loaded");

  // English, then dark theme, through the page's own buttons.
  await cdp.evaluate(`document.getElementById("lang").click()`);
  s = await waitFor(cdp, `document.documentElement.lang === "en" && document.documentElement.dir === "ltr"`, "English").then(state);
  await cdp.screenshot(`${out}/02-start-en.png`);
  check(s.dir === "ltr", "English, left to right");
  await cdp.evaluate(`document.getElementById("theme").click()`);
  await waitFor(cdp, `document.documentElement.dataset.theme === "dark"`, "dark theme");
  s = await state();
  await cdp.screenshot(`${out}/03-start-en-dark.png`);
  check(s.background === "rgb(15, 23, 22)", `dark theme applied (background ${s.background})`);

  // An invalid link shows the error in the page.
  await cdp.evaluate(`document.getElementById("link").value = "not a link"; document.querySelector("#f-setup button[type=submit]").click()`);
  const err = await waitFor(cdp, `(() => { const e = document.getElementById("error"); return !e.hidden && e.textContent; })()`, "an error message");
  await cdp.screenshot(`${out}/04-invalid-link.png`);
  check(err.length > 10, `error shown: ${err}`);

  // Settings and About pages.
  await cdp.evaluate(`document.getElementById("b-settings").click()`);
  await waitFor(cdp, `!document.querySelector('section[data-page="settings"]').hidden`, "settings");
  await cdp.screenshot(`${out}/05-settings.png`);
  await cdp.evaluate(`document.querySelector('[data-page-go="about"]').click()`);
  const about = await waitFor(cdp, `(() => { const a = document.querySelector('section[data-page="about"]'); return !a.hidden && a.textContent; })()`, "about");
  await cdp.screenshot(`${out}/06-about.png`);
  check(about.includes("Yaman Astaif"), "About names the developer");
  check(/Version \d+\.\d+\.\d+/.test(about), "About shows the version");
  check(about.includes("0.8.0"), "About shows the server version needed");

  // Back to the first screen in Arabic (check-screens.mjs checks every
  // screen at the window's size).
  await cdp.evaluate(`window.hifaz.showPage(""); window.hifaz.onView({ screen: "setup" }); document.getElementById("lang").click()`);
  await waitFor(cdp, `document.documentElement.lang === "ar" && document.documentElement.dir === "rtl"`, "Arabic");

  // Back to the light theme for the next start (the language is Arabic again).
  await cdp.evaluate(`document.getElementById("theme").click()`);
} finally {
  cdp.close();
}
if (failures.length) {
  console.log(`${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("UI start checks passed.");
