package winui

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/app"
)

// message is what the page sends: an app.Action, or one of the window's
// own requests.
type message struct {
	app.Action
	Prefs *Prefs `json:"prefs,omitempty"`
	URL   string `json:"url,omitempty"`
	// Message is a page error's text (page_error).
	Message string `json:"message,omitempty"`
}

// Window-level requests; everything else goes to the app.
const (
	msgReady    = "ready"      // the page has loaded: send it everything
	msgSetPrefs = "set_prefs"  // language, theme, start with Windows
	msgOpenURL  = "open_url"   // open the administrator's download page
	msgError    = "page_error" // a script error in the page, for the log
)

// maxPageError bounds how much of a page error goes to the log.
const maxPageError = 300

// route decides what a page message asks for. It returns exactly one of:
// ready, new prefs, a URL to open, a page error, or an app action. Anything malformed or
// not allowed is dropped (ok false).
type routed struct {
	ready  bool
	prefs  *Prefs
	url    string
	err    string
	action *app.Action
}

// route parses a page message. allowedURL is the only address the page may
// open: the download link of the current update screen.
func route(raw string, allowedURL string) (routed, bool) {
	var m message
	if json.Unmarshal([]byte(raw), &m) != nil || m.Name == "" {
		return routed{}, false
	}
	switch m.Name {
	case msgReady:
		return routed{ready: true}, true
	case msgSetPrefs:
		if m.Prefs == nil || !m.Prefs.Valid() {
			return routed{}, false
		}
		return routed{prefs: m.Prefs}, true
	case msgOpenURL:
		u, err := url.Parse(m.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || m.URL != allowedURL {
			return routed{}, false
		}
		return routed{url: m.URL}, true
	case msgError:
		e := strings.ToValidUTF8(m.Message, "?")
		if len(e) > maxPageError {
			e = strings.ToValidUTF8(e[:maxPageError], "")
		}
		if e == "" {
			e = "unknown"
		}
		return routed{err: e}, true
	}
	a := m.Action
	return routed{action: &a}, true
}

// allowedDownload returns the download link a view offers, if any.
func allowedDownload(v *app.View) string {
	if v != nil && v.Screen == app.ScreenUpdateRequired && v.Update != nil {
		return v.Update.DownloadURL
	}
	return ""
}
