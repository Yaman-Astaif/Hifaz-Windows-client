"use strict";

// Texts of the window, in Arabic (the default) and English. Errors and
// notices are keyed by the codes the app sends.
window.I18N = (function () {
  const T = {
    ar: {
      switchTo: "English",
      loading: "جارٍ التحميل…",
      settings: "الإعدادات",
      theme: "المظهر",
      language: "اللغة",
      themeSystem: "حسب الجهاز",
      themeLight: "فاتح",
      themeDark: "داكن",
      autostart: "تشغيل حِفاظ عند بدء Windows",
      about: "حول التطبيق",
      back: "رجوع",
      cancel: "إلغاء",
      continue: "متابعة",
      confirm: "تأكيد",
      server: "الخادم",
      user: "المستخدم",
      device: "الجهاز",
      password: "كلمة المرور",
      code: "رمز التحقق",
      codeOptional: "(إن كنت تستخدم المصادقة الثنائية)",

      setupTitle: "إضافة هذا الجهاز",
      setupSub: "الصق رابط التسجيل الذي أرسله إليك المسؤول.",
      link: "رابط التسجيل",
      replaceWarning: "سيحل الخادم الجديد محل الخادم المسجَّل الآن على هذا الجهاز بعد إتمام التسجيل.",

      fpTitle: "تحقّق من هوية الخادم",
      fpSub: "هذا الرابط لا يحمل بصمة الخادم. قارن البصمة التالية بالبصمة التي أعطاك إياها المسؤول.",
      fpHint: "يجدها المسؤول في صفحة «حول» في لوحة التحكم، أو بالأمر hifaz server identity.",
      fpMatches: "البصمة مطابقة، متابعة",
      fpDiffers: "البصمة مختلفة، إلغاء",

      enrollTitle: "تفعيل هذا الجهاز",
      enrollSub: "أدخل كلمة المرور التي استلمتها من المسؤول.",
      devName: "اسم هذا الجهاز",
      devNameHint: "بأحرف إنجليزية، مثلاً Work laptop.",
      mfaTitle: "إعداد المصادقة الثنائية",
      mfaSub: "يتطلب حسابك رمزاً من تطبيق المصادقة عند كل تسجيل دخول.",
      mfaStep1: "افتح تطبيق Microsoft Authenticator أو Google Authenticator على هاتفك.",
      mfaStep2: "امسح هذا الرمز، أو أدخل المفتاح يدوياً.",
      mfaStep3: "أدخل الرمز المكوّن من 6 أرقام الظاهر في التطبيق.",
      qrLabel: "رمز QR لتطبيق المصادقة",

      signInTitle: "تسجيل الدخول",
      signInSub: "سجّل الدخول لفتح اتصالك الآمن.",
      connect: "اتصال",
      otpTitle: "رمز التحقق",
      otpSub: "أدخل الرمز الظاهر في تطبيق المصادقة.",

      connected: "متصل",
      vpnAddress: "عنوان الشبكة",
      connectedSince: "متصل منذ",
      sessionEnds: "تنتهي الجلسة",
      traffic: "البيانات",
      trafficValue: "↓ {rx}  ↑ {tx}",
      routes: "الشبكات المتاحة",
      idleNote: "يُقطع الاتصال تلقائياً بعد {idle} دون استخدام، أو عند انتهاء الجلسة.",
      disconnect: "قطع الاتصال وتسجيل الخروج",
      minutes: (n) => (n === 1 ? "دقيقة واحدة" : n === 2 ? "دقيقتين" : n <= 10 ? n + " دقائق" : n + " دقيقة"),

      updateTitle: "يلزم تحديث التطبيق",
      updateText: "يتطلب هذا الخادم الإصدار {min} من حِفاظ أو أحدث. الإصدار المثبّت: {current}.",
      download: "فتح صفحة التنزيل",

      thisDevice: "هذا الجهاز",
      fingerprint: "بصمة الخادم",
      keysExpire: "تنتهي المفاتيح",
      addServer: "التسجيل بخادم آخر",
      removeDevice: "إزالة الجهاز من هذا الحاسوب",
      removeConfirm: "ستُحذف مفاتيح هذا الجهاز من هذا الحاسوب، وستحتاج إلى رابط تسجيل جديد. هل تريد المتابعة؟",

      developer: "المطوّر",
      version: "الإصدار {v}",
      aboutText: "حِفاظ بوابة WireGuard: يفتح النفق بعد تسجيل الدخول فقط، ويُغلقه عند الخروج أو الخمول أو انتهاء المدة.",
      thirdParty: "مكوّنات من جهات أخرى",
      creditWireGuard: "برنامج التشغيل WireGuardNT ومكتبة wireguard.dll الرسمية، كما هي",
      trademark: "WireGuard علامة تجارية مسجّلة لـ Jason A. Donenfeld. حِفاظ غير تابع لمشروع WireGuard.",

      // notices
      enrolled: "تم تفعيل هذا الجهاز. سجّل الدخول للاتصال.",
      signed_out: "انتهت الجلسة: تم تسجيل الخروج.",
      idle: "انتهت الجلسة بسبب عدم الاستخدام.",
      time_limit: "انتهت مدة الجلسة.",
      ended_by_admin: "أنهى المسؤول الجلسة.",
      device_disabled: "عطّل المسؤول هذا الجهاز.",
      user_disabled: "عطّل المسؤول حسابك.",
      group_changed: "تغيّرت صلاحيات حسابك. سجّل الدخول من جديد.",
      ended: "انتهت الجلسة.",

      // errors (server)
      invalid_credentials: "تعذّر تسجيل الدخول. تحقّق من كلمة المرور والرمز، ثم حاول مجدداً.",
      invalid_signature: "رفض الخادم توقيع هذا الجهاز. قد يكون الجهاز معطّلاً أو محذوفاً؛ تواصل مع المسؤول.",
      clock_skew: "ساعة هذا الحاسوب غير مضبوطة (وقت الخادم {time}). اضبط التاريخ والوقت ثم حاول مجدداً.",
      invalid_session: "انتهت الجلسة. سجّل الدخول من جديد.",
      invalid_link: "هذا الرابط غير صالح أو مستخدم أو منتهي الصلاحية. اطلب رابطاً جديداً من المسؤول.",
      invalid_step: "انتهت مهلة هذه الخطوة. الصق الرابط من جديد.",
      invalid_code: "الرمز غير مطابق. تأكد من ضبط الوقت على هاتفك، ثم أدخل الرمز الحالي.",
      invalid_device_choice: "الاسم يقبل من 1 إلى 64 حرفاً إنجليزياً أو رقماً أو مسافة أو . _ -",
      device_name_taken: "لديك جهاز آخر بهذا الاسم. اختر اسماً مختلفاً.",
      use_browser: "هذا الرابط يُفتح في المتصفح، لا في التطبيق.",
      keys_expired: "انتهت صلاحية مفاتيح هذا الجهاز. اطلب من المسؤول رابط تجديد والصقه هنا.",
      method_not_allowed: "لا تسمح مجموعتك بهذه الطريقة في الاتصال. تواصل مع المسؤول.",
      app_too_old: "يلزم تحديث التطبيق.",
      unsupported_protocol: "هذا الخادم لا يدعم هذا الإصدار من التطبيق.",
      rate_limited: "محاولات كثيرة. انتظر {secs} ثانية ثم حاول مجدداً.",
      invalid_csr: "رفض الخادم طلب شهادة هذا الجهاز. تواصل مع المسؤول.",
      unknown_device: "هذا الجهاز معطّل أو مفاتيحه غير معروفة لدى الخادم. تواصل مع المسؤول.",
      cert_required: "تتطلب مجموعتك شهادة جهاز لم تصل إلى الخادم. تواصل مع المسؤول.",
      cert_invalid: "شهادة هذا الجهاز ملغاة أو منتهية. اطلب من المسؤول رابط تجديد.",
      cert_unchecked: "لا يستطيع الخادم التحقق من شهادة الجهاز حالياً (إعداد الخادم). تواصل مع المسؤول.",
      bad_request: "رفض الخادم الطلب. حدّث التطبيق أو تواصل مع المسؤول.",
      not_found: "هذا الخادم لا يدعم التطبيق. تحقّق من أن المسؤول حدّث حِفاظ إلى 0.8.0 أو أحدث.",
      timeout: "الخادم مشغول. حاول مجدداً بعد قليل.",
      // errors (service)
      busy: "يستخدم مستخدم آخر على هذا الحاسوب اتصال حِفاظ الآن.",
      not_registered: "هذا الجهاز غير مسجّل لدى خدمة حِفاظ على هذا الحاسوب. سجّله من جديد برابط تسجيل.",
      verify_failed: "تعذّر التحقق من ردّ الخادم، فلم يُفتح النفق.",
      server_not_allowed: "لا يسمح مسؤول هذا الحاسوب بهذا الخادم.",
      full_tunnel: "يطلب الخادم تمرير كل الاتصالات عبر النفق، ولا يسمح مسؤول هذا الحاسوب بذلك.",
      bad_config: "أرسل الخادم إعداداً غير صالح. تواصل مع المسؤول.",
      tunnel_failed: "تعذّر فتح النفق على هذا الحاسوب. حاول مجدداً، وإن تكرر فتواصل مع المسؤول.",
      not_owner: "انتهى الاتصال. سجّل الدخول من جديد.",
      // errors (app)
      network: "تعذّر الاتصال بالخادم. تحقّق من اتصالك بالإنترنت.",
      identity_mismatch: "هوية الخادم لا تطابق البصمة المسجّلة. لم يُرسَل شيء. تواصل مع المسؤول.",
      bad_signature: "ردّ الخادم غير موقّع بمفتاحه المعروف. لم يُرسَل شيء. تواصل مع المسؤول.",
      service_unavailable: "خدمة حِفاظ لا تعمل على هذا الحاسوب. أعد تشغيل الحاسوب أو أعد تثبيت التطبيق.",
      no_account: "لا يوجد جهاز مسجّل. الصق رابط تسجيل.",
      keystore: "تعذّر فتح مفاتيح هذا الجهاز.",
      internal: "حدث خطأ غير متوقع. حاول مجدداً.",
      server_error: "حدث خطأ في الخادم. حاول مجدداً بعد قليل.",
    },
    en: {
      switchTo: "العربية",
      loading: "Loading…",
      settings: "Settings",
      theme: "Theme",
      language: "Language",
      themeSystem: "Same as device",
      themeLight: "Light",
      themeDark: "Dark",
      autostart: "Start Hifaz with Windows",
      about: "About",
      back: "Back",
      cancel: "Cancel",
      continue: "Continue",
      confirm: "Confirm",
      server: "Server",
      user: "User",
      device: "Device",
      password: "Password",
      code: "Verification code",
      codeOptional: "(if you use two-step verification)",

      setupTitle: "Add this device",
      setupSub: "Paste the enrollment link your administrator sent you.",
      link: "Enrollment link",
      replaceWarning: "Once enrollment is done, the new server replaces the one this device uses now.",

      fpTitle: "Check the server's identity",
      fpSub: "This link has no server fingerprint. Compare the one below with the fingerprint your administrator gave you.",
      fpHint: "Administrators find it on the dashboard's About page, or with hifaz server identity.",
      fpMatches: "It matches, continue",
      fpDiffers: "It differs, cancel",

      enrollTitle: "Activate this device",
      enrollSub: "Enter the password you received from your administrator.",
      devName: "Name of this device",
      devNameHint: "In English letters, for example Work laptop.",
      mfaTitle: "Set up two-step verification",
      mfaSub: "Your account needs a code from an authenticator app at every sign-in.",
      mfaStep1: "Open Microsoft Authenticator or Google Authenticator on your phone.",
      mfaStep2: "Scan this code, or enter the key by hand.",
      mfaStep3: "Enter the 6-digit code the app shows.",
      qrLabel: "QR code for the authenticator app",

      signInTitle: "Sign in",
      signInSub: "Sign in to open your secure connection.",
      connect: "Connect",
      otpTitle: "Verification code",
      otpSub: "Enter the code your authenticator app shows.",

      connected: "Connected",
      vpnAddress: "Network address",
      connectedSince: "Connected since",
      sessionEnds: "Session ends",
      traffic: "Data",
      trafficValue: "↓ {rx}  ↑ {tx}",
      routes: "Networks reached",
      idleNote: "The connection closes by itself after {idle} without use, or when the session ends.",
      disconnect: "Disconnect and sign out",
      minutes: (n) => (n === 1 ? "1 minute" : n + " minutes"),

      updateTitle: "Update needed",
      updateText: "This server needs Hifaz {min} or newer. Installed: {current}.",
      download: "Open the download page",

      thisDevice: "This device",
      fingerprint: "Server fingerprint",
      keysExpire: "Keys expire",
      addServer: "Enroll with another server",
      removeDevice: "Remove the device from this computer",
      removeConfirm: "This device's keys will be deleted from this computer, and you will need a new enrollment link. Continue?",

      developer: "Developer",
      version: "Version {v}",
      aboutText: "Hifaz is a WireGuard gateway: the tunnel opens only after you sign in, and closes on sign-out, when idle, or when time runs out.",
      thirdParty: "Third-party components",
      creditWireGuard: "the official WireGuardNT driver and wireguard.dll, unmodified",
      trademark: "WireGuard is a registered trademark of Jason A. Donenfeld. Hifaz is not affiliated with the WireGuard project.",

      enrolled: "This device is active. Sign in to connect.",
      signed_out: "Session ended: signed out.",
      idle: "The session ended because it was not used.",
      time_limit: "The session reached its time limit.",
      ended_by_admin: "An administrator ended the session.",
      device_disabled: "An administrator disabled this device.",
      user_disabled: "An administrator disabled your account.",
      group_changed: "Your access changed. Sign in again.",
      ended: "The session ended.",

      invalid_credentials: "Sign-in failed. Check the password and code, then try again.",
      invalid_signature: "The server refused this device's signature. The device may be disabled or removed; contact your administrator.",
      clock_skew: "This computer's clock is off (server time {time}). Set the date and time, then try again.",
      invalid_session: "The session ended. Sign in again.",
      invalid_link: "This link is invalid, used or expired. Ask your administrator for a new one.",
      invalid_step: "This step timed out. Paste the link again.",
      invalid_code: "The code does not match. Check the time on your phone, then enter the current code.",
      invalid_device_choice: "The name takes 1 to 64 English letters, digits, spaces or . _ -",
      device_name_taken: "You have another device with this name. Choose a different one.",
      use_browser: "This link opens in the browser, not in the app.",
      keys_expired: "This device's keys have expired. Ask your administrator for a renewal link and paste it here.",
      method_not_allowed: "Your group does not allow this way of connecting. Contact your administrator.",
      app_too_old: "The app needs an update.",
      unsupported_protocol: "This server does not support this version of the app.",
      rate_limited: "Too many attempts. Wait {secs} seconds, then try again.",
      invalid_csr: "The server refused this device's certificate request. Contact your administrator.",
      unknown_device: "This device is disabled, or the server does not know its keys. Contact your administrator.",
      cert_required: "Your group needs a device certificate that did not reach the server. Contact your administrator.",
      cert_invalid: "This device's certificate is revoked or expired. Ask your administrator for a renewal link.",
      cert_unchecked: "The server cannot check device certificates right now (server setup). Contact your administrator.",
      bad_request: "The server refused the request. Update the app or contact your administrator.",
      not_found: "This server does not support the app. Check that your administrator updated Hifaz to 0.8.0 or later.",
      timeout: "The server is busy. Try again in a moment.",
      busy: "Another user on this computer is using the Hifaz connection right now.",
      not_registered: "This device is not registered with the Hifaz service on this computer. Enroll it again with a link.",
      verify_failed: "The server's answer could not be verified, so the tunnel was not opened.",
      server_not_allowed: "This computer's administrator does not allow this server.",
      full_tunnel: "The server wants all traffic through the tunnel, which this computer's administrator does not allow.",
      bad_config: "The server sent an unusable configuration. Contact your administrator.",
      tunnel_failed: "The tunnel could not be opened on this computer. Try again; if it keeps failing, contact your administrator.",
      not_owner: "The connection ended. Sign in again.",
      network: "The server cannot be reached. Check your internet connection.",
      identity_mismatch: "The server's identity does not match the recorded fingerprint. Nothing was sent. Contact your administrator.",
      bad_signature: "The server's answer is not signed with its known key. Nothing was sent. Contact your administrator.",
      service_unavailable: "The Hifaz service is not running on this computer. Restart the computer or reinstall the app.",
      no_account: "No device is enrolled. Paste an enrollment link.",
      keystore: "This device's keys could not be opened.",
      internal: "Something unexpected happened. Try again.",
      server_error: "The server had an error. Try again in a moment.",
    },
  };

  let lang = "ar";

  function t(key, vars) {
    let s = T[lang][key];
    if (s === undefined) s = T.en[key];
    if (s === undefined) return "";
    if (typeof s === "function") return s(vars);
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (vars[k] !== undefined ? String(vars[k]) : m));
    return s;
  }

  // errorText translates an error code; unknown codes fall back to a
  // general message (server-side HTTP errors become server_error).
  function errorText(e) {
    if (!e || !e.code) return "";
    let code = e.code;
    if (code.startsWith("http_")) code = "server_error";
    if (T[lang][code] === undefined) code = "internal";
    const time = e.server_time ? new Date(e.server_time).toLocaleString(locale()) : "";
    return t(code, { time, secs: e.retry_after || 60 });
  }

  function setLang(l) { lang = T[l] ? l : "ar"; }
  function getLang() { return lang; }
  function locale() { return lang === "ar" ? "ar" : "en-GB"; }
  function has(key) { return T[lang][key] !== undefined; }

  return { t, errorText, setLang, getLang, locale, has };
})();
