package winui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
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

func TestStatusPixels(t *testing.T) {
	for _, connected := range []bool{true, false} {
		px := statusPixels(32, connected)
		if len(px) != 32*32*4 {
			t.Fatal("size")
		}
		alpha := func(x, y int) byte { return px[(y*32+x)*4+3] }
		if alpha(0, 0) != 0 || alpha(31, 31) != 0 {
			t.Error("corners must be transparent")
		}
		if alpha(16, 2) == 0 {
			t.Error("edge of the dot not drawn")
		}
		if centre := alpha(16, 16); connected != (centre == 255) {
			t.Errorf("connected=%v: centre alpha %d", connected, centre)
		}
	}
	if text("fr", "quit") != "Quit" || text("ar", "quit") != "إنهاء" {
		t.Fatal("texts")
	}
}
