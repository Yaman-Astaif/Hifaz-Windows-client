package tunnel

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// Name Resolution Policy Table (NRPT): the Windows DNS client resolves names
// under a rule's namespaces with the rule's servers only. Hifaz keeps one
// rule under a fixed key, so it only ever changes or removes its own.
const (
	nrptLocal = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	// Rules set by Group Policy; while any exist, Windows ignores local ones.
	nrptGroupPolicy = `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig`
	nrptRuleKey     = `{DE105279-EF28-4AD4-A74D-47C351D88095}`
	nrptComment     = "Hifaz - managed by the Hifaz service"
)

var (
	moddnsapi                 = windows.NewLazySystemDLL("dnsapi.dll")
	procDnsFlushResolverCache = moddnsapi.NewProc("DnsFlushResolverCache")
)

// GroupPolicyNRPT reports whether Group Policy sets NRPT rules, in which
// case Windows ignores Hifaz's local rule.
func GroupPolicyNRPT() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptGroupPolicy, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(1)
	return err == nil && len(names) > 0
}

// setRule writes Hifaz's rule.
func setRule(r *Rule) error {
	servers := make([]string, len(r.Servers))
	for i, s := range r.Servers {
		servers[i] = s.String()
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	for _, set := range []func() error{
		func() error { return k.SetDWordValue("Version", 2) },
		func() error { return k.SetStringsValue("Name", r.Namespaces) },
		func() error { return k.SetStringValue("GenericDNSServers", strings.Join(servers, ";")) },
		func() error { return k.SetDWordValue("ConfigOptions", 0x8) }, // generic DNS servers
		func() error { return k.SetStringValue("IPSECCARestriction", "") },
		func() error { return k.SetStringValue("Comment", nrptComment) },
	} {
		if err := set(); err != nil {
			removeRule()
			return err
		}
	}
	return nil
}

// removeRule deletes Hifaz's rule if present.
func removeRule() error {
	err := registry.DeleteKey(registry.LOCAL_MACHINE, nrptLocal+`\`+nrptRuleKey)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return err
}

// notifyDNS tells the DNS client that its settings changed and flushes its
// cache, so the change applies to the next lookup.
func notifyDNS() {
	if m, err := mgr.Connect(); err == nil {
		name, _ := windows.UTF16PtrFromString("Dnscache")
		if h, err := windows.OpenService(m.Handle, name, windows.SERVICE_PAUSE_CONTINUE); err == nil {
			s := mgr.Service{Name: "Dnscache", Handle: h}
			s.Control(svc.ParamChange)
			s.Close()
		}
		m.Disconnect()
	}
	procDnsFlushResolverCache.Call()
}
