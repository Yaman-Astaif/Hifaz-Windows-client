"use strict";

// The window draws whatever View the app sends (window.hifaz.onView) and
// sends the user's actions back. It keeps no app state of its own, and it
// only ever sets text, never HTML.
(function () {
  const { t, errorText, setLang, getLang, locale } = window.I18N;
  const $ = (id) => document.getElementById(id);
  const all = (sel) => Array.from(document.querySelectorAll(sel));

  let view = { screen: "loading" };
  let prefs = { lang: "ar", theme: "system", autostart: true };
  let app = { version: "", developer: "" };
  let page = ""; // "", "settings" or "about": pages of the window itself
  let lastScreen = "";

  function send(msg) {
    if (window.chrome && window.chrome.webview) window.chrome.webview.postMessage(JSON.stringify(msg));
  }
  const act = (name, params) => send(Object.assign({ action: name }, params || {}));

  // Errors in the page go to the app's log.
  window.addEventListener("error", (ev) => {
    send({ action: "page_error", message: String(ev.message || "") + " @" + (ev.lineno || 0) });
  });

  // --- formatting --------------------------------------------------------------------

  function host(url) {
    try { return new URL(url).host; } catch (e) { return url || ""; }
  }
  function when(s) {
    if (!s) return "";
    const d = new Date(s);
    return isNaN(d) ? "" : d.toLocaleString(locale(), { dateStyle: "medium", timeStyle: "short" });
  }
  function bytes(n) {
    n = n || 0;
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
  }
  function spaced(secret) {
    return (secret || "").replace(/(.{4})/g, "$1 ").trim();
  }

  // model flattens the view into the values the page shows.
  function model() {
    const m = {};
    const put = (k, v) => { if (v !== undefined && v !== null && v !== "" && v !== false) m[k] = v; };
    const a = view.account;
    if (a) {
      put("account", true);
      put("account.host", host(a.server));
      put("account.username", a.username);
      put("account.device", a.device);
      put("account.fingerprint", a.fingerprint);
      put("account.keys_expire_text", when(a.keys_expire_at));
    }
    const e = view.enroll;
    if (e) {
      put("enroll.server", host(e.server));
      put("enroll.username", e.username);
      put("enroll.device", e.device);
      put("enroll.name_editable", e.name_editable);
      // Two-step verification was set up in an interrupted attempt: the code is required.
      put("enroll.code_required", !!e.code_required);
      put("enroll.code_optional", !e.code_required);
      put("enroll.renew", e.kind === "renew");
      put("enroll.new_device", e.kind !== "renew");
      put("enroll.renew_text", e.kind === "renew" && e.device ? t("renewDevice", { device: "\u2068" + e.device + "\u2069" }) : "");
      put("enroll.device_row", e.kind !== "renew" && !!e.device); // a renewal names the device in its subtitle
      put("enroll.fingerprint_display", (e.fingerprint || "").replace(/(.{4})/g, "$1 ").trim());
      put("enroll.mfa_secret_spaced", spaced(e.mfa_secret));
    }
    const s = view.session;
    if (s) {
      put("session.address", s.address);
      put("session.connected_at_text", when(s.connected_at));
      put("session.expires_at_text", when(s.expires_at));
      put("session.traffic_text", t("trafficValue", { rx: bytes(s.rx_bytes), tx: bytes(s.tx_bytes) }));
      put("session.routes_text", (s.allowed_ips || []).join("\n"));
      if (s.idle_timeout_seconds) {
        put("session.idle_note", t("idleNote", { idle: t("minutes", Math.max(1, Math.round(s.idle_timeout_seconds / 60))) }));
      }
    }
    const u = view.update;
    if (u) {
      put("update.text", t("updateText", { min: u.min_version, current: app.version }));
      put("update.download_url", u.download_url);
    }
    put("replacing", view.replacing);
    put("first_setup", !view.replacing); // the returning-user hint is for a computer with no enrollment
    put("app.version_text", app.version ? t("version", { v: app.version }) : "");
    put("app.developer", app.developer);
    put("app.requires_text", app.min_server ? t("requiresServer", { v: app.min_server }) : "");
    return m;
  }

  // --- drawing -------------------------------------------------------------------

  function translate() {
    document.documentElement.lang = getLang();
    document.documentElement.dir = getLang() === "ar" ? "rtl" : "ltr";
    all("[data-t]").forEach((el) => { el.textContent = t(el.dataset.t); });
    all("[data-t-label]").forEach((el) => {
      el.setAttribute("aria-label", t(el.dataset.tLabel));
      el.title = t(el.dataset.tLabel);
    });
    const lang = $("lang");
    lang.textContent = t("switchTo");
    lang.lang = getLang() === "ar" ? "en" : "ar";
  }

  function applyTheme() {
    const root = document.documentElement;
    if (prefs.theme === "light" || prefs.theme === "dark") root.dataset.theme = prefs.theme;
    else delete root.dataset.theme;
    const dark = prefs.theme === "dark" ||
      (prefs.theme !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
    // SVG elements have no .hidden property: set the attribute.
    document.querySelector(".i-moon").toggleAttribute("hidden", dark);
    document.querySelector(".i-sun").toggleAttribute("hidden", !dark);
  }

  function render() {
    translate();
    applyTheme();
    const m = model();
    all("section[data-screen]").forEach((s) => { s.hidden = page !== "" || s.dataset.screen !== view.screen; });
    all("section[data-page]").forEach((s) => { s.hidden = s.dataset.page !== page; });
    all("[data-field]").forEach((el) => { el.textContent = m[el.dataset.field] || ""; });
    all("[data-show]").forEach((el) => { el.hidden = !m[el.dataset.show]; });

    const err = $("error");
    err.textContent = errorText(view.error);
    err.hidden = !view.error || page !== "";
    const note = $("notice");
    note.textContent = view.notice && window.I18N.has(view.notice) ? t(view.notice) : "";
    note.hidden = !note.textContent || !!view.error || page !== "";

    document.body.classList.toggle("busy", !!view.busy);
    all("input, select, button").forEach((el) => { el.disabled = !!view.busy && !el.closest("header"); });

    $("e-otp").required = !!(view.enroll && view.enroll.code_required);
    if (view.screen === "enroll_mfa" && view.enroll && view.enroll.mfa_uri) drawQR(view.enroll.mfa_uri);

    $("p-lang").value = prefs.lang;
    $("p-theme").value = prefs.theme;
    $("p-autostart").checked = !!prefs.autostart;

    if (view.screen !== lastScreen) {
      clearSecrets();
      lastScreen = view.screen;
      // After a timed-out or interrupted enrollment the app sends the link
      // back: the user only presses Continue.
      const prefilled = view.screen === "setup" && !!view.link;
      if (prefilled) $("link").value = view.link;
      const first = prefilled ? document.querySelector('#f-setup button[type="submit"]')
        : document.querySelector('section[data-screen="' + view.screen + '"] input');
      if (first && page === "") first.focus();
    } else if (!view.busy && view.screen === "signin_otp" && view.error && page === "") {
      // The step is kept after a wrong code or a passing error: the field
      // (cleared when the code was sent) is ready for the next one.
      $("o-code").focus();
    }
  }

  // Passwords and codes do not stay in the page once the screen changes.
  function clearSecrets() {
    all('input[type="password"], input.code').forEach((el) => { el.value = ""; });
  }

  function drawQR(uri) {
    const canvas = $("qr");
    if (canvas.dataset.uri === uri || typeof qrcode !== "function") return;
    const qr = qrcode(0, "M");
    qr.addData(uri);
    qr.make();
    const n = qr.getModuleCount();
    const scale = Math.floor(canvas.width / (n + 8));
    const offset = Math.floor((canvas.width - n * scale) / 2);
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#000000";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) ctx.fillRect(offset + c * scale, offset + r * scale, scale, scale);
      }
    }
    canvas.dataset.uri = uri;
  }

  // --- user actions ----------------------------------------------------------------

  function onSubmit(id, f) {
    $(id).addEventListener("submit", (ev) => { ev.preventDefault(); if (!view.busy) f(); });
  }
  onSubmit("f-setup", () => act("enroll_link", { link: $("link").value.trim() }));
  onSubmit("f-enroll", () => act("enroll_password",
    { password: $("e-password").value, otp: $("e-otp").value, device_name: $("e-name").value }));
  onSubmit("f-mfa", () => act("enroll_mfa", { code: $("m-code").value, device_name: $("e-name").value }));
  onSubmit("f-signin", () => act("signin", { password: $("s-password").value, otp: $("s-otp").value }));
  // The code is cleared once sent: Windows may merge the busy view into the
  // answer, so clearing cannot wait for a busy-to-idle change.
  onSubmit("f-otp", () => {
    const code = $("o-code");
    const otp = code.value;
    code.value = "";
    act("signin_otp", { otp });
  });

  all("[data-act]").forEach((el) => el.addEventListener("click", () => {
    if (el.dataset.act === "add_server" || el.dataset.act === "enroll_cancel") page = "";
    act(el.dataset.act);
  }));
  all("[data-page-go]").forEach((el) => el.addEventListener("click", () => { page = el.dataset.pageGo; render(); }));
  $("b-settings").addEventListener("click", () => { page = page === "settings" ? "" : "settings"; render(); });
  $("b-download").addEventListener("click", () => {
    if (view.update && view.update.download_url) send({ action: "open_url", url: view.update.download_url });
  });

  // Removing the device needs a second click within a few seconds.
  let removeArmed = 0;
  $("b-remove").addEventListener("click", (ev) => {
    const b = ev.currentTarget;
    if (Date.now() - removeArmed < 6000) {
      removeArmed = 0;
      page = "";
      act("remove_account");
      return;
    }
    removeArmed = Date.now();
    b.textContent = t("removeConfirm");
    setTimeout(() => { if (removeArmed && Date.now() - removeArmed >= 6000) { removeArmed = 0; b.textContent = t("removeDevice"); } }, 6100);
  });

  function setPrefs(p) {
    prefs = Object.assign({}, prefs, p);
    setLang(prefs.lang);
    send({ action: "set_prefs", prefs });
    render();
  }
  $("lang").addEventListener("click", () => setPrefs({ lang: getLang() === "ar" ? "en" : "ar" }));
  $("theme").addEventListener("click", () => {
    const dark = !document.querySelector(".i-sun").hasAttribute("hidden");
    setPrefs({ theme: dark ? "light" : "dark" });
  });
  $("p-lang").addEventListener("change", (ev) => setPrefs({ lang: ev.target.value }));
  $("p-theme").addEventListener("change", (ev) => setPrefs({ theme: ev.target.value }));
  $("p-autostart").addEventListener("change", (ev) => setPrefs({ autostart: ev.target.checked }));
  window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);

  // --- from the app --------------------------------------------------------------------

  window.hifaz = {
    onView(v) {
      view = v || {};
      // A screen the page does not have shows as loading, never as nothing.
      if (!all("section[data-screen]").some((s) => s.dataset.screen === view.screen)) {
        view = Object.assign({}, view, { screen: "loading" });
      }
      render();
    },
    onPrefs(p) { prefs = Object.assign({}, prefs, p); setLang(prefs.lang); render(); },
    onApp(a) { app = Object.assign({}, app, a); render(); },
    showPage(p) { page = p || ""; render(); },
  };

  setLang(prefs.lang);
  render();
  send({ action: "ready" });
})();
