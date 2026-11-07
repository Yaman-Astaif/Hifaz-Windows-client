// Package winui is the Windows face of the app: the window (WebView2), the
// tray icon and menu, and the app's own preferences. The decisions are in
// the platform-independent files here and tested anywhere; the *_windows.go
// files only talk to Windows.
package winui

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Prefs are the user's choices for the window.
type Prefs struct {
	Lang      string `json:"lang"`      // "ar" or "en"
	Theme     string `json:"theme"`     // "system", "light" or "dark"
	Autostart bool   `json:"autostart"` // start with Windows
}

// DefaultPrefs: Arabic, the device's theme, starting with Windows.
func DefaultPrefs() Prefs { return Prefs{Lang: "ar", Theme: "system", Autostart: true} }

// Valid reports whether every field has an allowed value.
func (p Prefs) Valid() bool {
	return (p.Lang == "ar" || p.Lang == "en") && (p.Theme == "system" || p.Theme == "light" || p.Theme == "dark")
}

// LoadPrefs reads the preferences, or returns the defaults.
func LoadPrefs(path string) Prefs {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultPrefs()
	}
	p := DefaultPrefs()
	if json.Unmarshal(data, &p) != nil || !p.Valid() {
		return DefaultPrefs()
	}
	return p
}

// SavePrefs writes the preferences.
func SavePrefs(path string, p Prefs) error {
	if !p.Valid() {
		return errors.New("invalid preferences")
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
