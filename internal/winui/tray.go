package winui

import (
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
)

// trayText holds the tray's words in both languages.
var trayText = map[string]map[string]string{
	"ar": {
		"open":         "فتح حِفاظ",
		"connect":      "اتصال…",
		"disconnect":   "قطع الاتصال",
		"quit":         "إنهاء",
		"connected":    "حِفاظ - متصل",
		"disconnected": "حِفاظ - غير متصل",
		"waiting":      "حِفاظ - بانتظار الخادم",
		"noAnswer":     "حِفاظ - الخادم لا يردّ",
		"noWebView":    "يحتاج حِفاظ إلى Microsoft Edge WebView2 Runtime. ثبّته من موقع Microsoft ثم شغّل حِفاظ مجدداً.",
	},
	"en": {
		"open":         "Open Hifaz",
		"connect":      "Connect…",
		"disconnect":   "Disconnect",
		"quit":         "Quit",
		"connected":    "Hifaz - connected",
		"disconnected": "Hifaz - not connected",
		"waiting":      "Hifaz - waiting for the server",
		"noAnswer":     "Hifaz - the server doesn't answer",
		"noWebView":    "Hifaz needs the Microsoft Edge WebView2 Runtime. Install it from Microsoft, then start Hifaz again.",
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
