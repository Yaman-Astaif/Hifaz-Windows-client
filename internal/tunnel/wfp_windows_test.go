package tunnel

import (
	"os"
	"testing"
	"unsafe"
)

// The hand-written WFP structures must match the Windows headers (sizes and
// offsets of FWPM_* on x64 and arm64, as in wireguard-windows'
// tunnel/firewall/types_windows_64.go).
func TestWFPLayout(t *testing.T) {
	var p fwpmProvider0
	var v fwpValue0
	var c fwpmFilterCondition0
	var a fwpmAction0
	var f fwpmFilter0
	var e fwpmFilterEnumTemplate0
	for _, tc := range []struct {
		name      string
		got, want uintptr
	}{
		{"FWPM_PROVIDER0", unsafe.Sizeof(p), 64},
		{"FWPM_PROVIDER0.displayData", unsafe.Offsetof(p.displayData), 16},
		{"FWP_VALUE0", unsafe.Sizeof(v), 16},
		{"FWP_VALUE0.value", unsafe.Offsetof(v.value), 8},
		{"FWPM_FILTER_CONDITION0", unsafe.Sizeof(c), 40},
		{"FWPM_FILTER_CONDITION0.matchType", unsafe.Offsetof(c.matchType), 16},
		{"FWPM_FILTER_CONDITION0.conditionValue", unsafe.Offsetof(c.conditionValue), 24},
		{"FWPM_ACTION0", unsafe.Sizeof(a), 20},
		{"FWPM_FILTER0.displayData", unsafe.Offsetof(f.displayData), 16},
		{"FWPM_FILTER0.providerKey", unsafe.Offsetof(f.providerKey), 40},
		{"FWPM_FILTER0.layerKey", unsafe.Offsetof(f.layerKey), 64},
		{"FWPM_FILTER0.numFilterConditions", unsafe.Offsetof(f.numFilterConditions), 112},
		{"FWPM_FILTER0.filterCondition", unsafe.Offsetof(f.filterCondition), 120},
		{"FWPM_FILTER0.action", unsafe.Offsetof(f.action), 128},
		{"FWPM_FILTER_ENUM_TEMPLATE0", unsafe.Sizeof(e), 72},
		{"FWPM_FILTER_ENUM_TEMPLATE0.layerKey", unsafe.Offsetof(e.layerKey), 8},
		{"FWPM_FILTER_ENUM_TEMPLATE0.enumType", unsafe.Offsetof(e.enumType), 24},
		{"FWPM_FILTER_ENUM_TEMPLATE0.numFilterConditions", unsafe.Offsetof(e.numFilterConditions), 40},
		{"FWPM_FILTER_ENUM_TEMPLATE0.actionMask", unsafe.Offsetof(e.actionMask), 56},
		{"FWPM_FILTER_ENUM_TEMPLATE0.calloutKey", unsafe.Offsetof(e.calloutKey), 64},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

// TestFindKillSwitch reads the machine's WFP state, which needs
// administrator rights. The CI machine has no WireGuard app.
func TestFindKillSwitch(t *testing.T) {
	if os.Getenv("HIFAZ_TUNNEL_TEST") != "1" {
		t.Skip("set HIFAZ_TUNNEL_TEST=1 (administrator)")
	}
	providers, filters, err := readWFP()
	if err != nil {
		t.Fatal(err)
	}
	if len(providers) == 0 {
		t.Fatal("no WFP providers read; Windows always has some")
	}
	t.Logf("%d providers, %d outbound connection filters", len(providers), len(filters))
	b, err := New(nil).FindKillSwitch()
	if err != nil || b != nil {
		t.Fatalf("FindKillSwitch = %+v, %v; want nothing found", b, err)
	}
}
