package winui

import (
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

// trayText holds the tray's words in both languages.
var trayText = map[string]map[string]string{
	"ar": {
		"notifyKeysExpired":    "انتهت صلاحية مفاتيح جهاز حِفاظ. اطلب رابط تجديد من المسؤول.",
		"notifyServerEnded":    "لم تعد جلسة حِفاظ نشطة على الخادم. سجّل الدخول مجددًا.",
		"notifyAccessDisabled": "أوقف الخادم الوصول إلى حِفاظ. تواصل مع المسؤول.",
		"notifyGroupChanged":   "تغيّرت صلاحيات الوصول إلى حِفاظ. سجّل الدخول مجددًا.",
		"notifyConnected":      "اتصل حِفاظ.",
		"notifyDisconnected":   "قُطع الاتصال بحِفاظ وسُجّل الخروج.",
		"notifyNoAnswer":       "لا يستجيب خادم حِفاظ. افتح التشخيص لمعرفة السبب.",
		"notifyAdminEnded":     "أنهى الخادم جلسة حِفاظ. سجّل الدخول مجددًا.",
		"notifyTest":           "هذا إشعار اختباري من حِفاظ.",
		"notifyTitle":          "حِفاظ",
		"notifyBlocked":        "تحظر شبكة VPN أخرى الاتصال. افتح التشخيص لمعرفة السبب.",
		"notifyRestored":       "استُعيد اتصال حِفاظ.",
		"notifyExpired":        "انتهت جلسة حِفاظ. افتح التطبيق لتسجيل الدخول.",
		"notifyLost":           "انقطع اتصال حِفاظ. افتح التشخيص لمعرفة السبب.",
		"open":                 "فتح حِفاظ",
		"connect":              "اتصال…",
		"disconnect":           "قطع الاتصال",
		"quit":                 "إنهاء",
		"connected":            "حِفاظ - متصل",
		"disconnected":         "حِفاظ - غير متصل",
		"waiting":              "حِفاظ - بانتظار الخادم",
		"noAnswer":             "حِفاظ - الخادم لا يردّ",
		"noWebView":            "يحتاج حِفاظ إلى Microsoft Edge WebView2 Runtime. ثبّته من موقع Microsoft ثم شغّل حِفاظ مجدداً.",
	},
	"en": {
		"notifyKeysExpired":    "Your Hifaz device keys expired. Ask your administrator for a renewal link.",
		"notifyServerEnded":    "Your Hifaz session is no longer active on the server. Sign in again.",
		"notifyAccessDisabled": "The server disabled access to Hifaz. Contact your administrator.",
		"notifyGroupChanged":   "Your Hifaz access changed. Sign in again.",
		"notifyConnected":      "Hifaz is connected.",
		"notifyDisconnected":   "Hifaz disconnected and signed out.",
		"notifyNoAnswer":       "The Hifaz server is not responding. Open Diagnostics for details.",
		"notifyAdminEnded":     "The server ended your Hifaz session. Sign in again.",
		"notifyTest":           "This is a test notification from Hifaz.",
		"notifyTitle":          "Hifaz",
		"notifyBlocked":        "Another VPN is blocking the connection. Open Diagnostics for details.",
		"notifyRestored":       "Hifaz reconnected automatically.",
		"notifyExpired":        "Your Hifaz session ended. Open the app to sign in.",
		"notifyLost":           "Hifaz lost its connection. Open Diagnostics for details.",
		"open":                 "Open Hifaz",
		"connect":              "Connect…",
		"disconnect":           "Disconnect",
		"quit":                 "Quit",
		"connected":            "Hifaz - connected",
		"disconnected":         "Hifaz - not connected",
		"waiting":              "Hifaz - waiting for the server",
		"noAnswer":             "Hifaz - the server doesn't answer",
		"noWebView":            "Hifaz needs the Microsoft Edge WebView2 Runtime. Install it from Microsoft, then start Hifaz again.",
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
func connectionNotification(before, after app.View, background, wasUp, interruptionNotified bool) (key, page string) {
	if after.Screen == app.ScreenConnected && after.Session != nil {
		switch ipc.Link(after.Session.Link) {
		case ipc.LinkNoAnswer:
			if interruptionNotified {
				return "", ""
			}
			if after.Session.Blocker != nil && (before.Session == nil || before.Session.Blocker == nil) {
				return "notifyBlocked", "diagnostics"
			}
			if background && (before.Session == nil || before.Session.Link != after.Session.Link) {
				return "notifyNoAnswer", "diagnostics"
			}
		case ipc.LinkUp, "":
			if interruptionNotified {
				return "notifyRestored", "diagnostics"
			}
			if background && !wasUp {
				return "notifyConnected", ""
			}
		}
	}
	if before.Screen != app.ScreenConnected || after.Screen != app.ScreenSignIn {
		return "", ""
	}
	switch after.Notice {
	case "signed_out_here":
		return "", ""
	case "signed_out_from_tray":
		return "notifyDisconnected", ""
	case "idle", "time_limit":
		return "notifyExpired", ""
	case "ended_by_admin":
		return "notifyAdminEnded", ""
	case "device_disabled", "user_disabled":
		return "notifyAccessDisabled", ""
	case "group_changed":
		return "notifyGroupChanged", ""
	case "keys_expired":
		return "notifyKeysExpired", ""
	case "":
		if after.Error == nil {
			return "", ""
		}
		if after.Error.Code == protocol.ErrCodeInvalidSession {
			return "notifyServerEnded", ""
		}
	default:
		return "notifyServerEnded", ""
	}
	if background {
		return "notifyLost", "diagnostics"
	}
	return "", ""
}
