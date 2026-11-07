// Package version holds the app's name and version and compares versions.
package version

import (
	"errors"
	"strconv"
	"strings"
)

// Version is set at build time:
//
//	-ldflags "-X github.com/Yaman-Astaif/Hifaz-Windows-client/internal/version.Version=0.1.0"
var Version = "0.0.0-dev"

// Fixed names. Platform is the platform key of the client protocol.
const (
	Name      = "Hifaz - حِفاظ"
	AppName   = "Hifaz for Windows" // sent to the server at enrollment
	Developer = "Yaman Astaif"
	Platform  = "windows"
)

// UserAgent identifies the app in HTTP requests.
func UserAgent() string { return "Hifaz-Windows/" + Version }

// Compare compares two versions of the form X.Y.Z (an optional "v" prefix
// and a "-suffix" are allowed; a version with a suffix sorts before the same
// version without one). It returns -1, 0 or 1.
func Compare(a, b string) (int, error) {
	pa, sa, err := parse(a)
	if err != nil {
		return 0, err
	}
	pb, sb, err := parse(b)
	if err != nil {
		return 0, err
	}
	for i := range pa {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	switch {
	case sa == sb:
		return 0, nil
	case sa == "":
		return 1, nil
	case sb == "":
		return -1, nil
	case sa < sb:
		return -1, nil
	default:
		return 1, nil
	}
}

func parse(v string) ([3]uint64, string, error) {
	var out [3]uint64
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, suffix, _ := strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, "", errors.New("version must be X.Y.Z")
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || (len(p) > 1 && p[0] == '0') {
			return out, "", errors.New("version must be X.Y.Z")
		}
		out[i] = n
	}
	return out, suffix, nil
}
