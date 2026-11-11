package winui

import (
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// debugEnv names a port on which the page can be inspected (the UI tests
// use it). WebView2's own variable for browser arguments cannot be used:
// the WebView2 library clears it when the program starts.
const debugEnv = "HIFAZ_WEBVIEW_DEBUG_PORT"

// debugPortArg returns the browser argument for a debugging port when env
// is a port number from 1024 to 65535, else "". The port listens on the
// local machine only.
func debugPortArg(env string) string {
	n, err := strconv.Atoi(strings.TrimSpace(env))
	if err != nil || n < 1024 || n > 65535 {
		return ""
	}
	return "--remote-debugging-port=" + strconv.Itoa(n)
}

// The page is served under a reserved name (.invalid never resolves), from
// files embedded in the app; nothing is loaded from anywhere else.
const (
	pageOrigin = "https://hifaz.invalid"
	pageURL    = pageOrigin + "/index.html"
	pageCSP    = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
)

// Content types by extension, so serving does not depend on the Windows
// registry's file associations.
var contentTypes = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".woff2": "font/woff2",
	".svg":   "image/svg+xml",
	".png":   "image/png",
}

// resolvePage maps a request address from the web view to an embedded
// file. It returns the file and its content type, or an error saying why
// the address is not served.
func resolvePage(files fs.FS, raw string) (body []byte, ctype string, err error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("bad address: %w", err)
	}
	if !strings.EqualFold(u.Scheme+"://"+u.Host, pageOrigin) {
		return nil, "", errors.New("not the app's page origin")
	}
	name := strings.TrimPrefix(path.Clean("/"+u.Path), "/")
	if name == "" {
		name = "index.html"
	}
	body, err = fs.ReadFile(files, name)
	if err != nil {
		return nil, "", err
	}
	ctype = contentTypes[path.Ext(name)]
	if ctype == "" {
		ctype = mime.TypeByExtension(path.Ext(name))
	}
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	return body, ctype, nil
}
