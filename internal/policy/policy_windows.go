package policy

import (
	"errors"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// RegistryKey is where administrators set the policy (HKEY_LOCAL_MACHINE),
// by hand, Group Policy or device management:
//
//	AllowFullTunnel  REG_DWORD     1 to allow full tunnels
//	Servers          REG_MULTI_SZ  "<public URL> <fingerprint>"
const RegistryKey = `SOFTWARE\Policies\Hifaz`

// Load reads the policy. A missing key is the default policy. An entry that
// cannot be read makes Load fail closed: the policy then allows no server,
// so a typing mistake never opens more than the administrator meant.
func Load() (Policy, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, RegistryKey, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return Policy{}, nil
	}
	if err != nil {
		return denyAll(), err
	}
	defer k.Close()
	var p Policy
	if v, _, err := k.GetIntegerValue("AllowFullTunnel"); err == nil {
		p.AllowFullTunnel = v == 1
	} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return denyAll(), err
	}
	entries, _, err := k.GetStringsValue("Servers")
	if err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return denyAll(), err
	}
	for _, e := range entries {
		if e == "" {
			continue
		}
		s, err := ParseServer(e)
		if err != nil {
			return denyAll(), err
		}
		p.Servers = append(p.Servers, s)
	}
	return p, nil
}

// denyAll is a policy no server satisfies.
func denyAll() Policy {
	return Policy{Servers: []Server{{URL: "invalid:"}}}
}
