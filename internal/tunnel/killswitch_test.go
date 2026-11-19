package tunnel

import (
	"reflect"
	"testing"
)

// wireGuardFilters is what the WireGuard app adds for a tunnel with
// "Block untunneled traffic" on (tunnel/firewall in wireguard-windows),
// limited to the outbound connection layers: the permits for its own
// service, loopback, DHCP and its adapter, then block all.
func wireGuardFilters(provider GUID, luid uint64) []wfpFilter {
	p := &provider
	var f []wfpFilter
	for _, layer := range []GUID{layerALEAuthConnectV4, layerALEAuthConnectV6} {
		f = append(f,
			wfpFilter{Provider: p, Layer: layer, Action: actionPermit, Conditions: []wfpCondition{
				{Field: GUID{Data1: 0xd78e1e87}, Type: 12}, {Field: GUID{Data1: 0xaf043a0a}, Type: 14}}},
			wfpFilter{Provider: p, Layer: layer, Action: actionPermit, Conditions: []wfpCondition{
				{Field: GUID{Data1: 0x632ce23b}, Type: 3}}},
			wfpFilter{Provider: p, Layer: layer, Action: actionPermit, Conditions: []wfpCondition{
				{Field: conditionIPLocalInterface, Match: matchEqual, Type: fwpUint64, Uint64: luid}}},
			wfpFilter{Provider: p, Layer: layer, Action: actionBlock},
		)
	}
	return f
}

func TestKillSwitch(t *testing.T) {
	wg := GUID{Data1: 0x11111111}
	other := GUID{Data1: 0x22222222}
	const wgLUID, ownLUID = 0x0006_0000_0100_0000, 0x0006_0000_0200_0000
	providers := []wfpProvider{{Key: wg, Name: "WireGuard"}, {Key: other, Name: "Some firewall"}}

	for _, tc := range []struct {
		name      string
		providers []wfpProvider
		filters   []wfpFilter
		found     bool
		luids     []uint64
	}{
		{"found", providers, wireGuardFilters(wg, wgLUID), true, []uint64{wgLUID}},
		{"two tunnels", append(providers, wfpProvider{Key: GUID{Data1: 3}, Name: "WireGuard"}),
			append(wireGuardFilters(wg, wgLUID), wireGuardFilters(GUID{Data1: 3}, wgLUID+1)...), true, []uint64{wgLUID, wgLUID + 1}},
		{"provider not named WireGuard", []wfpProvider{{Key: wg, Name: "WireGuard filters"}}, wireGuardFilters(wg, wgLUID), false, nil},
		{"another app's block all", providers, wireGuardFilters(other, wgLUID), false, nil},
		{"no provider", providers, func() []wfpFilter {
			f := wireGuardFilters(wg, wgLUID)
			for i := range f {
				f[i].Provider = nil
			}
			return f
		}(), false, nil},
		{"no block-all filter", providers, func() []wfpFilter {
			f := wireGuardFilters(wg, wgLUID)
			var keep []wfpFilter
			for _, x := range f {
				if x.Action != actionBlock {
					keep = append(keep, x)
				}
			}
			return keep
		}(), false, nil},
		{"a block filter with conditions", providers, func() []wfpFilter {
			f := wireGuardFilters(wg, wgLUID)
			for i := range f {
				if f[i].Action == actionBlock {
					f[i].Conditions = []wfpCondition{{Field: GUID{Data1: 0xb235ae9a}, Type: 3}}
				}
			}
			return f
		}(), false, nil},
		{"block all in another layer", providers, func() []wfpFilter {
			f := wireGuardFilters(wg, wgLUID)
			for i := range f {
				f[i].Layer = GUID{Data1: 0xe1cd9fe7} // inbound
			}
			return f
		}(), false, nil},
		{"no permit for the adapter: found, no name", providers, func() []wfpFilter {
			f := wireGuardFilters(wg, wgLUID)
			for i := range f {
				if len(f[i].Conditions) == 1 && f[i].Conditions[0].Field == conditionIPLocalInterface {
					f[i].Conditions[0].Type = 3 // not a LUID
				}
			}
			return f
		}(), true, nil},
		{"Hifaz's own adapter left out", providers, wireGuardFilters(wg, ownLUID), true, nil},
		{"nothing", nil, nil, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, luids := killSwitch(tc.providers, tc.filters, ownLUID)
			if found != tc.found || !reflect.DeepEqual(luids, tc.luids) {
				t.Fatalf("killSwitch = %v %x, want %v %x", found, luids, tc.found, tc.luids)
			}
		})
	}
}
