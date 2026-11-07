// Package sysinfo reads what the app needs from the system: the Windows
// version text and the user's proxy settings.
package sysinfo

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// ProxyFunc returns the proxy for each request, from Windows' "manual
// proxy" settings (ProxyServer and ProxyOverride). server is empty when no
// proxy is set.
func ProxyFunc(server, override string) func(*http.Request) (*url.URL, error) {
	proxy := pickProxy(server)
	if proxy == nil {
		return nil
	}
	bypass := strings.FieldsFunc(override, func(r rune) bool { return r == ';' || r == ' ' })
	return func(r *http.Request) (*url.URL, error) {
		if bypassed(r.URL.Hostname(), bypass) {
			return nil, nil
		}
		return proxy, nil
	}
}

// pickProxy reads "host:port", or a per-protocol list such as
// "http=a:80;https=b:8080", and returns the proxy for HTTPS.
func pickProxy(server string) *url.URL {
	server = strings.TrimSpace(server)
	if server == "" {
		return nil
	}
	chosen := server
	if strings.Contains(server, "=") {
		chosen = ""
		for _, part := range strings.Split(server, ";") {
			proto, addr, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				continue
			}
			switch strings.ToLower(proto) {
			case "https":
				chosen = addr
			case "http":
				if chosen == "" {
					chosen = addr
				}
			}
		}
	}
	if chosen == "" {
		return nil
	}
	if !strings.Contains(chosen, "://") {
		chosen = "http://" + chosen
	}
	u, err := url.Parse(chosen)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	return u
}

// bypassed applies ProxyOverride: "<local>" (names without a dot), exact
// names, and "*" wildcards.
func bypassed(host string, rules []string) bool {
	host = strings.ToLower(host)
	for _, r := range rules {
		r = strings.ToLower(strings.TrimSpace(r))
		switch {
		case r == "":
		case r == "<local>":
			if !strings.Contains(host, ".") && net.ParseIP(host) == nil {
				return true
			}
		case strings.Contains(r, "*"):
			if wildcard(r, host) {
				return true
			}
		case r == host:
			return true
		}
	}
	return false
}

// wildcard matches s against a pattern where * stands for any run of
// characters.
func wildcard(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 { // last part: must end the string
			return strings.HasSuffix(s, p)
		}
		idx := strings.Index(s, p)
		if idx < 0 {
			return false
		}
		s = s[idx+len(p):]
	}
	return true
}
