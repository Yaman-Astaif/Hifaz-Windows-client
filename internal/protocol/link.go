package protocol

import (
	"errors"
	"net/url"
	"strings"
)

// NormalizeServerURL checks a server's public URL and returns its canonical
// form: https, lower-case host, no user info, query, fragment or trailing
// slash. A path prefix (a server behind a proxy under /vpn, say) is kept.
func NormalizeServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("invalid server address")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("server address must use https")
	}
	if u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("invalid server address")
	}
	host := strings.ToLower(u.Host)
	if u.Port() == "443" {
		host = strings.TrimSuffix(host, ":443")
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	return "https://" + host + path, nil
}

// enrollPath is where enrollment links point, below the public URL.
const enrollPath = "/login/enroll"

// maxTokenLen bounds the link token; real tokens are 43 characters.
const maxTokenLen = 128

// EnrollLink is a parsed enrollment link:
// <public_url>/login/enroll#<token>[.<fingerprint>]
type EnrollLink struct {
	Server      string      // normalized public URL
	Token       string      // the link token, as the API wants it
	Fingerprint Fingerprint // empty for links made before Hifaz 0.8.0
}

// ParseEnrollLink parses a link pasted by the user.
func ParseEnrollLink(raw string) (EnrollLink, error) {
	var l EnrollLink
	invalid := errors.New("this is not a Hifaz enrollment link")
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return l, invalid
	}
	fragment := u.Fragment
	u.Fragment, u.RawFragment = "", ""
	path := strings.TrimRight(u.EscapedPath(), "/")
	if !strings.HasSuffix(path, enrollPath) {
		return l, invalid
	}
	u.Path, u.RawPath = strings.TrimSuffix(path, enrollPath), ""
	if l.Server, err = NormalizeServerURL(u.String()); err != nil {
		return l, err
	}
	token, fp, hasFP := strings.Cut(fragment, ".")
	if !validToken(token) {
		return l, invalid
	}
	l.Token = token
	if hasFP {
		if l.Fingerprint, err = ParseFingerprint(fp); err != nil {
			return l, invalid
		}
	}
	return l, nil
}

func validToken(s string) bool {
	if s == "" || len(s) > maxTokenLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
