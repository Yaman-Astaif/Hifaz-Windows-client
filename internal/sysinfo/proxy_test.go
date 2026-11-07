package sysinfo

import (
	"net/http"
	neturl "net/url"
	"testing"
)

func TestProxy(t *testing.T) {
	if ProxyFunc("", "") != nil {
		t.Fatal("no proxy expected")
	}
	get := func(f func(*http.Request) (*neturl.URL, error), host string) string {
		r, _ := http.NewRequest("GET", "https://"+host+"/", nil)
		u, _ := f(r)
		if u == nil {
			return ""
		}
		return u.String()
	}
	f := ProxyFunc("proxy.corp:8080", "<local>;*.corp.example;10.*;vpn.example.com")
	for host, want := range map[string]string{
		"vpn.other.com":      "http://proxy.corp:8080",
		"intranet":           "",
		"a.corp.example":     "",
		"10.1.2.3":           "",
		"vpn.example.com":    "",
		"vpn.example.com.au": "http://proxy.corp:8080",
	} {
		if got := get(f, host); got != want {
			t.Errorf("%s: %q, want %q", host, got, want)
		}
	}
	f = ProxyFunc("http=a.corp:80;https=b.corp:8443", "")
	if got := get(f, "x.example.com"); got != "http://b.corp:8443" {
		t.Errorf("per-protocol: %q", got)
	}
	if ProxyFunc("ftp=a:21", "") != nil {
		t.Error("no HTTP(S) proxy in the list must mean no proxy")
	}
}
