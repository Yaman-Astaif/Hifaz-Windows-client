package tunnel

import "slices"

// Another VPN's kill switch. The WireGuard app, for a tunnel with
// "Block untunneled traffic" on (the default with a /0 route), adds Windows
// Filtering Platform (WFP) filters that block every outbound connection not
// made through its own adapter. Hifaz's packets are then dropped before they
// reach the Hifaz adapter, and the server never answers. Hifaz only reads
// these filters, to say why; it never changes or works around them.
//
// The filters are recognized by what they do, not by their names
// (wireguard-windows, tunnel/firewall: blocker.go and rules.go): a provider
// named "WireGuard" (a new key for every tunnel) owns a block filter with no
// conditions in an outbound connection layer, "block all". The same
// provider's permit filter whose only condition is the local interface names
// the tunnel's adapter by its LUID.

// GUID is a Windows GUID, laid out as windows.GUID.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WFP values read (fwpmu.h, fwptypes.h).
var (
	// FWPM_LAYER_ALE_AUTH_CONNECT_V4: outbound connections, IPv4.
	layerALEAuthConnectV4 = GUID{0xc38d57d1, 0x05a7, 0x4c33, [8]byte{0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}
	// FWPM_LAYER_ALE_AUTH_CONNECT_V6: outbound connections, IPv6.
	layerALEAuthConnectV6 = GUID{0x4a72393b, 0x319f, 0x44bc, [8]byte{0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}
	// FWPM_CONDITION_IP_LOCAL_INTERFACE: the interface's LUID.
	conditionIPLocalInterface = GUID{0x4cd62a49, 0x59c3, 0x4969, [8]byte{0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}}
)

const (
	actionBlock  = 0x1001 // FWP_ACTION_BLOCK
	actionPermit = 0x1002 // FWP_ACTION_PERMIT
	matchEqual   = 0      // FWP_MATCH_EQUAL
	fwpUint64    = 4      // FWP_UINT64

	wireGuardProvider = "WireGuard"
)

// wfpProvider and wfpFilter are the parts of WFP's providers and filters
// that the check reads.
type wfpProvider struct {
	Key  GUID
	Name string
}

type wfpFilter struct {
	Provider   *GUID // nil: no provider
	Layer      GUID
	Action     uint32
	Conditions []wfpCondition
}

type wfpCondition struct {
	Field  GUID
	Match  uint32
	Type   uint32
	Uint64 uint64 // the value, when Type is fwpUint64
}

// killSwitch reports whether a WireGuard kill switch is on, and the LUIDs
// of the adapters it lets through, in the order found, without own (Hifaz's
// adapter).
func killSwitch(providers []wfpProvider, filters []wfpFilter, own uint64) (found bool, luids []uint64) {
	wg := map[GUID]bool{}
	for _, p := range providers {
		if p.Name == wireGuardProvider {
			wg[p.Key] = true
		}
	}
	blocking := map[GUID]bool{}
	for _, f := range filters {
		if f.Provider != nil && wg[*f.Provider] && connectLayer(f.Layer) && f.Action == actionBlock && len(f.Conditions) == 0 {
			blocking[*f.Provider] = true
		}
	}
	if len(blocking) == 0 {
		return false, nil
	}
	for _, f := range filters {
		if f.Provider == nil || !blocking[*f.Provider] || !connectLayer(f.Layer) || f.Action != actionPermit || len(f.Conditions) != 1 {
			continue
		}
		c := f.Conditions[0]
		if c.Field != conditionIPLocalInterface || c.Match != matchEqual || c.Type != fwpUint64 || c.Uint64 == own {
			continue
		}
		if !slices.Contains(luids, c.Uint64) {
			luids = append(luids, c.Uint64)
		}
	}
	return true, luids
}

func connectLayer(g GUID) bool {
	return g == layerALEAuthConnectV4 || g == layerALEAuthConnectV6
}
