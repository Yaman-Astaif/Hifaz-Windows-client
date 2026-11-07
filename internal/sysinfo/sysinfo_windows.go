package sysinfo

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// OSName describes Windows for the server, for example
// "Windows 11 Pro 24H2 (26100)".
func OSName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows"
	}
	defer k.Close()
	product, _, _ := k.GetStringValue("ProductName")
	release, _, _ := k.GetStringValue("DisplayVersion")
	build, _, _ := k.GetStringValue("CurrentBuildNumber")
	// Windows 11 still reports "Windows 10" in ProductName; the build tells.
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if product == "" {
		product = "Windows"
	}
	out := strings.TrimSpace(product + " " + release)
	if build != "" {
		out += fmt.Sprintf(" (%s)", build)
	}
	return out
}

// UserProxy returns the current user's manual proxy settings as a proxy
// function, or nil when none is set. Proxy auto-configuration (PAC) scripts
// are not supported; pacSet reports whether one is set, so the app can log it.
func UserProxy() (proxy func(*http.Request) (*url.URL, error), pacSet bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return nil, false
	}
	defer k.Close()
	if pac, _, err := k.GetStringValue("AutoConfigURL"); err == nil && pac != "" {
		pacSet = true
	}
	enabled, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil || enabled == 0 {
		return nil, pacSet
	}
	server, _, _ := k.GetStringValue("ProxyServer")
	override, _, _ := k.GetStringValue("ProxyOverride")
	return ProxyFunc(server, override), pacSet
}
