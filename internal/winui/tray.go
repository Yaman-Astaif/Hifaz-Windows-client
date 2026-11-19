package winui

import (
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
)

// trayText holds the tray's words in both languages.
var trayText = map[string]map[string]string{
	"ar": {
		"notifyTitle":    "حِفاظ",
		"notifyBlocked":  "تحظر شبكة VPN أخرى الاتصال. افتح التشخيص لمعرفة السبب.",
		"notifyRestored": "استُعيد اتصال حِفاظ.",
		"notifyExpired":  "انتهت جلسة حِفاظ. افتح التطبيق لتسجيل الدخول.",
		"notifyLost":     "انقطع اتصال حِفاظ. افتح التشخيص لمعرفة السبب.",
		"open":           "فتح حِفاظ",
		"connect":        "اتصال…",
		"disconnect":     "قطع الاتصال",
		"quit":           "إنهاء",
		"connected":      "حِفاظ - متصل",
		"disconnected":   "حِفاظ - غير متصل",
		"waiting":        "حِفاظ - بانتظار الخادم",
		"noAnswer":       "حِفاظ - الخادم لا يردّ",
		"noWebView":      "يحتاج حِفاظ إلى Microsoft Edge WebView2 Runtime. ثبّته من موقع Microsoft ثم شغّل حِفاظ مجدداً.",
	},
	"en": {
		"notifyTitle":    "Hifaz",
		"notifyBlocked":  "Another VPN is blocking the connection. Open Diagnostics for details.",
		"notifyRestored": "Hifaz reconnected automatically.",
		"notifyExpired":  "Your Hifaz session ended. Open the app to sign in.",
		"notifyLost":     "Hifaz lost its connection. Open Diagnostics for details.",
		"open":           "Open Hifaz",
		"connect":        "Connect…",
		"disconnect":     "Disconnect",
		"quit":           "Quit",
		"connected":      "Hifaz - connected",
		"disconnected":   "Hifaz - not connected",
		"waiting":        "Hifaz - waiting for the server",
		"noAnswer":       "Hifaz - the server doesn't answer",
		"noWebView":      "Hifaz needs the Microsoft Edge WebView2 Runtime. Install it from Microsoft, then start Hifaz again.",
	},
}

func text(lang, key string) string {
	if s, ok := trayText[lang][key]; ok {
		return s
	}
	return trayText["en"][key]
}

// trayState gives the tray tip's key and whether to show the connected
// icon: only once the server answers through the tunnel.
func trayState(v app.View) (tipKey string, up bool) {
	if v.Screen != app.ScreenConnected {
		return "disconnected", false
	}
	if v.Session != nil {
		switch ipc.Link(v.Session.Link) {
		case ipc.LinkWaiting:
			return "waiting", false
		case ipc.LinkNoAnswer:
			return "noAnswer", false
		}
	}
	return "connected", true
}

// connectionNotification returns a message key and the page to open.
func connectionNotification(before, after app.View, blockedNotification bool) (key, page string) {
	if after.Screen == app.ScreenConnected && after.Session != nil {
		if !blockedNotification && after.Session.Blocker != nil && (before.Session == nil || before.Session.Blocker == nil) {
			return "notifyBlocked", "diagnostics"
		}
		if blockedNotification && (after.Session.Link == string(ipc.LinkUp) || after.Session.Link == "") {
			return "notifyRestored", "diagnostics"
		}
	}
	if before.Screen != app.ScreenConnected || after.Screen != app.ScreenSignIn {
		return "", ""
	}
	switch after.Notice {
	case "idle", "time_limit":
		return "notifyExpired", ""
	case "":
		if after.Error == nil {
			return "", "" // user signed out
		}
	}
	return "notifyLost", "diagnostics"
}
