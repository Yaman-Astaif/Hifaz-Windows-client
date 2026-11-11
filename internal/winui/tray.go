package winui

// trayText holds the tray's words in both languages.
var trayText = map[string]map[string]string{
	"ar": {
		"open":         "فتح حِفاظ",
		"connect":      "اتصال…",
		"disconnect":   "قطع الاتصال",
		"quit":         "إنهاء",
		"connected":    "حِفاظ - متصل",
		"disconnected": "حِفاظ - غير متصل",
		"noWebView":    "يحتاج حِفاظ إلى Microsoft Edge WebView2 Runtime. ثبّته من موقع Microsoft ثم شغّل حِفاظ مجدداً.",
	},
	"en": {
		"open":         "Open Hifaz",
		"connect":      "Connect…",
		"disconnect":   "Disconnect",
		"quit":         "Quit",
		"connected":    "Hifaz - connected",
		"disconnected": "Hifaz - not connected",
		"noWebView":    "Hifaz needs the Microsoft Edge WebView2 Runtime. Install it from Microsoft, then start Hifaz again.",
	},
}

func text(lang, key string) string {
	if s, ok := trayText[lang][key]; ok {
		return s
	}
	return trayText["en"][key]
}
