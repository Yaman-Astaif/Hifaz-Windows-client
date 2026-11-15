package tunnel

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/third_party/wireguard-windows/tunnel/winipcfg"
)

// Read-only access to the Windows Filtering Platform: the providers and the
// outbound connection filters, for killSwitch. Nothing is ever added,
// changed or removed. Only the structure fields read are mapped (fwpmtypes.h,
// fwptypes.h; the same layout on x64 and arm64, checked in the tests).

var (
	modfwpuclnt                        = windows.NewLazySystemDLL("fwpuclnt.dll")
	procFwpmEngineOpen0                = modfwpuclnt.NewProc("FwpmEngineOpen0")
	procFwpmEngineClose0               = modfwpuclnt.NewProc("FwpmEngineClose0")
	procFwpmProviderCreateEnumHandle0  = modfwpuclnt.NewProc("FwpmProviderCreateEnumHandle0")
	procFwpmProviderEnum0              = modfwpuclnt.NewProc("FwpmProviderEnum0")
	procFwpmProviderDestroyEnumHandle0 = modfwpuclnt.NewProc("FwpmProviderDestroyEnumHandle0")
	procFwpmFilterCreateEnumHandle0    = modfwpuclnt.NewProc("FwpmFilterCreateEnumHandle0")
	procFwpmFilterEnum0                = modfwpuclnt.NewProc("FwpmFilterEnum0")
	procFwpmFilterDestroyEnumHandle0   = modfwpuclnt.NewProc("FwpmFilterDestroyEnumHandle0")
	procFwpmFreeMemory0                = modfwpuclnt.NewProc("FwpmFreeMemory0")
)

const (
	rpcCAuthnWinNT           = 10 // RPC_C_AUTHN_WINNT
	fwpFilterEnumOverlapping = 1  // FWP_FILTER_ENUM_OVERLAPPING
	wfpEnumBatch             = 256
)

// FWPM_DISPLAY_DATA0
type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

// FWP_BYTE_BLOB
type fwpByteBlob struct {
	size uint32
	data *uint8
}

// FWPM_PROVIDER0
type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

// FWP_VALUE0 and FWP_CONDITION_VALUE0. value is a union: a pointer for
// 64-bit types (FWP_UINT64 is a UINT64*), the value itself for smaller ones.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

// FWPM_FILTER_CONDITION0
type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

// FWPM_ACTION0
type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

// FWPM_FILTER0, up to the action: only read through pointers Windows
// returns, never allocated here.
type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
}

// FWPM_FILTER_ENUM_TEMPLATE0
type fwpmFilterEnumTemplate0 struct {
	providerKey             *windows.GUID
	layerKey                windows.GUID
	enumType                uint32
	flags                   uint32
	providerContextTemplate uintptr
	numFilterConditions     uint32
	filterCondition         uintptr
	actionMask              uint32
	calloutKey              *windows.GUID
}

func wfpCall(p *windows.LazyProc, args ...uintptr) error {
	if err := p.Find(); err != nil {
		return err
	}
	r, _, _ := p.Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: %w", p.Name, windows.Errno(r))
	}
	return nil
}

// FindKillSwitch looks, read-only, for another WireGuard tunnel's kill
// switch, and names its tunnels when their adapters can be found. nil, nil
// when there is none.
func (t *Tunnel) FindKillSwitch() (*ipc.Blocker, error) {
	t.mu.Lock()
	own := uint64(t.luid)
	t.mu.Unlock()
	providers, filters, err := readWFP()
	if err != nil {
		return nil, err
	}
	found, luids := killSwitch(providers, filters, own)
	if !found {
		return nil, nil
	}
	b := &ipc.Blocker{App: ipc.BlockerWireGuard}
	for _, l := range luids {
		// The WireGuard app names its adapter after the tunnel.
		if row, err := winipcfg.LUID(l).Interface(); err == nil {
			if name := row.Alias(); name != "" {
				b.Tunnels = append(b.Tunnels, name)
			}
		}
	}
	return b, nil
}

// readWFP reads the providers and the filters of the outbound connection
// layers.
func readWFP() ([]wfpProvider, []wfpFilter, error) {
	var engine windows.Handle
	if err := wfpCall(procFwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&engine))); err != nil {
		return nil, nil, err
	}
	defer procFwpmEngineClose0.Call(uintptr(engine))
	providers, err := readProviders(engine)
	if err != nil {
		return nil, nil, err
	}
	var filters []wfpFilter
	for _, layer := range []GUID{layerALEAuthConnectV4, layerALEAuthConnectV6} {
		f, err := readFilters(engine, windows.GUID(layer))
		if err != nil {
			return nil, nil, err
		}
		filters = append(filters, f...)
	}
	return providers, filters, nil
}

func readProviders(engine windows.Handle) ([]wfpProvider, error) {
	var h windows.Handle
	if err := wfpCall(procFwpmProviderCreateEnumHandle0, uintptr(engine), 0, uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, err
	}
	defer procFwpmProviderDestroyEnumHandle0.Call(uintptr(engine), uintptr(h))
	var out []wfpProvider
	for {
		var entries **fwpmProvider0
		var n uint32
		if err := wfpCall(procFwpmProviderEnum0, uintptr(engine), uintptr(h), wfpEnumBatch,
			uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); err != nil {
			return nil, err
		}
		if n == 0 || entries == nil {
			return out, nil
		}
		for _, p := range unsafe.Slice(entries, n) {
			out = append(out, wfpProvider{Key: GUID(p.providerKey), Name: windows.UTF16PtrToString(p.displayData.name)})
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
	}
}

func readFilters(engine windows.Handle, layer windows.GUID) ([]wfpFilter, error) {
	tmpl := fwpmFilterEnumTemplate0{layerKey: layer, enumType: fwpFilterEnumOverlapping, actionMask: 0xFFFFFFFF}
	var h windows.Handle
	if err := wfpCall(procFwpmFilterCreateEnumHandle0, uintptr(engine), uintptr(unsafe.Pointer(&tmpl)), uintptr(unsafe.Pointer(&h))); err != nil {
		return nil, err
	}
	defer procFwpmFilterDestroyEnumHandle0.Call(uintptr(engine), uintptr(h))
	var out []wfpFilter
	for {
		var entries **fwpmFilter0
		var n uint32
		if err := wfpCall(procFwpmFilterEnum0, uintptr(engine), uintptr(h), wfpEnumBatch,
			uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&n))); err != nil {
			return nil, err
		}
		if n == 0 || entries == nil {
			return out, nil
		}
		for _, f := range unsafe.Slice(entries, n) {
			out = append(out, toFilter(f))
		}
		procFwpmFreeMemory0.Call(uintptr(unsafe.Pointer(&entries)))
	}
}

func toFilter(f *fwpmFilter0) wfpFilter {
	x := wfpFilter{Layer: GUID(f.layerKey), Action: f.action.typ}
	if f.providerKey != nil {
		k := GUID(*f.providerKey)
		x.Provider = &k
	}
	if f.numFilterConditions > 0 && f.filterCondition != nil {
		for _, c := range unsafe.Slice(f.filterCondition, f.numFilterConditions) {
			wc := wfpCondition{Field: GUID(c.fieldKey), Match: c.matchType, Type: c.conditionValue.typ}
			if c.conditionValue.typ == fwpUint64 {
				// The union holds a UINT64*: read it as a pointer.
				if p := *(*unsafe.Pointer)(unsafe.Pointer(&c.conditionValue.value)); p != nil {
					wc.Uint64 = *(*uint64)(p)
				}
			}
			x.Conditions = append(x.Conditions, wc)
		}
	}
	return x
}
