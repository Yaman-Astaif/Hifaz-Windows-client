package winui

import "math"

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

// statusPixels draws the tray icon: a filled dot when connected, a ring
// when not, anti-aliased, as size×size BGRA pixels with premultiplied alpha.
// (The app has no logo: the logo slot stays empty, so the icon only shows
// the state.)
func statusPixels(size int, connected bool) []byte {
	px := make([]byte, size*size*4)
	c := float64(size) / 2
	outer := c - 1
	inner := outer * 0.55       // the ring's hole
	r, g, b := 0x42, 0x81, 0x77 // forest green of the Hifaz palette
	if !connected {
		r, g, b = 0x8a, 0x8a, 0x8a
	}
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			d := math.Hypot(float64(x)+0.5-c, float64(y)+0.5-c)
			a := clamp01(outer - d + 0.5) // inside the outer edge
			if !connected {
				a *= clamp01(d - inner + 0.5) // outside the hole
			}
			i := (y*size + x) * 4
			px[i+0] = byte(float64(b) * a)
			px[i+1] = byte(float64(g) * a)
			px[i+2] = byte(float64(r) * a)
			px[i+3] = byte(255 * a)
		}
	}
	return px
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }
