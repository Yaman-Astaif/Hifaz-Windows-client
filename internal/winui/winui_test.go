package winui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ui"
)

func TestPrefs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Hifaz", "settings.json")
	if p := LoadPrefs(path); p != DefaultPrefs() {
		t.Fatalf("missing file: %+v", p)
	}
	want := Prefs{Lang: "en", Theme: "dark", Autostart: false}
	if err := SavePrefs(path, want); err != nil {
		t.Fatal(err)
	}
	if p := LoadPrefs(path); p != want {
		t.Fatalf("%+v", p)
	}
	if err := SavePrefs(path, Prefs{Lang: "fr", Theme: "dark"}); err == nil {
		t.Fatal("invalid prefs saved")
	}
	os.WriteFile(path, []byte(`{"lang":"xx"}`), 0o600)
	if p := LoadPrefs(path); p != DefaultPrefs() {
		t.Fatalf("invalid file: %+v", p)
	}
}

func TestRoute(t *testing.T) {
	const dl = "https://downloads.example.com/hifaz/"
	if r, ok := route(`{"action":"ready"}`, ""); !ok || !r.ready {
		t.Fatal("ready")
	}
	if r, ok := route(`{"action":"page_error","message":"`+strings.Repeat("x", 1000)+`"}`, ""); !ok || len(r.err) != maxPageError {
		t.Fatalf("page error: %d bytes", len(r.err))
	}
	if r, ok := route(`{"action":"set_prefs","prefs":{"lang":"en","theme":"light","autostart":true}}`, ""); !ok || r.prefs.Lang != "en" {
		t.Fatal("prefs")
	}
	if _, ok := route(`{"action":"set_prefs","prefs":{"lang":"de","theme":"light"}}`, ""); ok {
		t.Fatal("invalid prefs accepted")
	}
	if r, ok := route(`{"action":"open_url","url":"`+dl+`"}`, dl); !ok || r.url != dl {
		t.Fatal("allowed URL refused")
	}
	for _, u := range []string{"https://evil.example.com/", "http://downloads.example.com/hifaz/", "file:///C:/Windows/System32/calc.exe"} {
		if _, ok := route(`{"action":"open_url","url":"`+u+`"}`, dl); ok {
			t.Errorf("%s opened", u)
		}
	}
	if _, ok := route(`{"action":"open_url","url":"`+dl+`"}`, ""); ok {
		t.Fatal("URL opened while no update screen is shown")
	}
	if r, ok := route(`{"action":"signin","password":"pw","otp":"123456"}`, ""); !ok || r.action.Name != "signin" || r.action.Password != "pw" {
		t.Fatalf("action %+v", r.action)
	}
	for _, bad := range []string{``, `{}`, `nope`, `{"action":""}`} {
		if _, ok := route(bad, ""); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	v := &app.View{Screen: app.ScreenUpdateRequired, Update: &app.UpdateView{DownloadURL: dl}}
	if allowedDownload(v) != dl || allowedDownload(&app.View{Screen: app.ScreenSignIn, Update: v.Update}) != "" {
		t.Fatal("allowedDownload")
	}
}

func TestResolvePage(t *testing.T) {
	for _, raw := range []string{
		"https://hifaz.invalid/index.html", "https://hifaz.invalid/", "https://HIFAZ.invalid/index.html",
		"https://hifaz.invalid/assets/app.js", "https://hifaz.invalid/assets/style.css",
		"https://hifaz.invalid/assets/fonts/body-ar-400.woff2", "https://hifaz.invalid/index.html?x=1#y",
	} {
		body, ctype, err := resolvePage(ui.Files, raw)
		if err != nil || len(body) == 0 || ctype == "" {
			t.Errorf("%s: %d bytes, %q, %v", raw, len(body), ctype, err)
		}
	}
	if _, ctype, _ := resolvePage(ui.Files, pageURL); ctype != "text/html; charset=utf-8" {
		t.Errorf("index content type %q", ctype)
	}
	for _, raw := range []string{
		"https://hifaz.invalid/../../etc/passwd", "https://hifaz.invalid/nope.html",
		"https://evil.example.com/index.html", "http://hifaz.invalid/index.html", "::bad",
	} {
		if body, _, err := resolvePage(ui.Files, raw); err == nil && raw != "https://hifaz.invalid/../../etc/passwd" {
			t.Errorf("%s served (%d bytes)", raw, len(body))
		} else if err == nil && string(body[:15]) != "<!doctype html>" {
			t.Errorf("%s escaped the page tree", raw)
		}
	}
}

func TestViewBeforeWindowIsKept(t *testing.T) {
	b := newViewBox()
	if got := b.get().Screen; got != app.ScreenLoading {
		t.Fatalf("first view: %q, want loading", got)
	}
	b.set(app.View{Screen: app.ScreenSetup}) // the app is faster than the window
	calls := 0
	b.attach(func() { calls++ })
	if calls != 1 || b.get().Screen != app.ScreenSetup {
		t.Fatalf("after attach: %d calls, screen %q", calls, b.get().Screen)
	}
	b.set(app.View{Screen: app.ScreenSignIn})
	if calls != 2 || b.get().Screen != app.ScreenSignIn {
		t.Fatalf("after set: %d calls, screen %q", calls, b.get().Screen)
	}
}

func TestDebugPortArg(t *testing.T) {
	for env, want := range map[string]string{
		"":                          "",
		"9222":                      "--remote-debugging-port=9222",
		" 9222 ":                    "--remote-debugging-port=9222",
		"80":                        "",
		"70000":                     "",
		"9222 --x":                  "",
		"--remote-debugging-port=1": "",
	} {
		if got := debugPortArg(env); got != want {
			t.Errorf("debugPortArg(%q) = %q, want %q", env, got, want)
		}
	}
}

func TestTrayState(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    app.View
		tip  string
		up   bool
	}{
		{"signed out", app.View{Screen: app.ScreenSignIn}, "disconnected", false},
		{"connected, old service", app.View{Screen: app.ScreenConnected, Session: &app.SessionView{}}, "connected", true},
		{"connected", app.View{Screen: app.ScreenConnected, Session: &app.SessionView{Link: "up"}}, "connected", true},
		{"waiting", app.View{Screen: app.ScreenConnected, Session: &app.SessionView{Link: "waiting"}}, "waiting", false},
		{"no answer", app.View{Screen: app.ScreenConnected, Session: &app.SessionView{Link: "no_answer"}}, "noAnswer", false},
	} {
		tip, up := trayState(tc.v)
		if tip != tc.tip || up != tc.up {
			t.Errorf("%s: %q %v, want %q %v", tc.name, tip, up, tc.tip, tc.up)
		}
		for _, lang := range []string{"ar", "en"} {
			if trayText[lang][tip] == "" {
				t.Errorf("%s: no %s text for %q", tc.name, lang, tip)
			}
		}
	}
}

func TestConnectionNotification(t *testing.T) {
	up := app.View{Screen: app.ScreenConnected, Session: &app.SessionView{Link: "up"}}
	waiting := app.View{Screen: app.ScreenConnected, Session: &app.SessionView{Link: "waiting"}}
	noAnswer := app.View{Screen: app.ScreenConnected, Session: &app.SessionView{Link: "no_answer"}}
	blocked := app.View{Screen: app.ScreenConnected, Session: &app.SessionView{
		Link: "no_answer", Blocker: &app.BlockerView{App: "wireguard"},
	}}
	signIn := func(notice string) app.View { return app.View{Screen: app.ScreenSignIn, Notice: notice} }
	lost := app.View{Screen: app.ScreenSignIn, Error: &app.ViewError{Code: "network"}}
	for _, tc := range []struct {
		name                        string
		before, after               app.View
		background, wasUp, notified bool
		key, page                   string
	}{
		{"first handshake in background", waiting, up, true, false, false, "notifyConnected", ""},
		{"first handshake in window", waiting, up, false, false, false, "", ""},
		{"rekey", waiting, up, true, true, false, "", ""},
		{"blocker", up, blocked, false, true, false, "notifyBlocked", "diagnostics"},
		{"repeat", blocked, blocked, true, true, true, "", ""},
		{"background no answer", up, noAnswer, true, true, false, "notifyNoAnswer", "diagnostics"},
		{"foreground no answer", up, noAnswer, false, true, false, "", ""},
		{"recovery", blocked, up, true, true, true, "notifyRestored", "diagnostics"},
		{"unannounced recovery", blocked, up, true, true, false, "", ""},
		{"expiration", up, signIn("time_limit"), false, true, false, "notifyExpired", ""},
		{"admin termination", up, signIn("ended_by_admin"), false, true, false, "notifyAdminEnded", ""},
		{"background error", up, lost, true, true, false, "notifyLost", "diagnostics"},
		{"foreground error", up, lost, false, true, false, "", ""},
		{"tray sign-out", up, signIn("signed_out_from_tray"), true, true, false, "notifyDisconnected", ""},
		{"window sign-out", up, signIn("signed_out"), true, true, false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if key, page := connectionNotification(tc.before, tc.after, tc.background, tc.wasUp, tc.notified); key != tc.key || page != tc.page {
				t.Fatalf("got %q, %q; want %q, %q", key, page, tc.key, tc.page)
			}
			if tc.key != "" {
				for _, lang := range []string{"ar", "en"} {
					if trayText[lang][tc.key] == "" {
						t.Errorf("missing %s notification text for %q", lang, tc.key)
					}
				}
			}
		})
	}
}
