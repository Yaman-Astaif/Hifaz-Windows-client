package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/daemon"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/third_party/wireguard-windows/driver"
	"github.com/Yaman-Astaif/Hifaz-Windows-client/third_party/wireguard-windows/tunnel/winipcfg"
)

// The adapter has a fixed name and GUID: its own, never one of the official
// WireGuard app's, and the same on every start so Windows keeps one network
// profile for it.
const (
	AdapterName = "Hifaz"
	tunnelType  = "Hifaz"
)

var adapterGUID = windows.GUID{Data1: 0xB5E55B6D, Data2: 0x49B2, Data3: 0x485D,
	Data4: [8]byte{0xAC, 0x04, 0x36, 0xCB, 0xF4, 0x58, 0xCF, 0x6B}}

const (
	resolveTimeout = 10 * time.Second
	// Right after the adapter comes up its IP interfaces may not exist yet.
	interfaceRetries = 20
	interfaceRetry   = 250 * time.Millisecond
)

// Tunnel is the Windows implementation of daemon.Tunnel.
type Tunnel struct {
	log func(msg string, args ...any)

	mu        sync.Mutex
	adapter   *driver.Adapter
	luid      winipcfg.LUID
	plan      *Plan
	peer      protocol.Key // server public key
	endpoint  netip.AddrPort
	host      string // endpoint host as configured
	priv, psk protocol.Key
}

var _ daemon.Tunnel = (*Tunnel)(nil)

// New returns a Tunnel; log may be nil.
func New(log func(msg string, args ...any)) *Tunnel {
	if log == nil {
		log = func(string, ...any) {}
	}
	return &Tunnel{log: log}
}

// Up implements daemon.Tunnel. Every sign-in comes here with a new
// adapter: the engine always takes the previous tunnel down first, and
// closing the adapter deletes it with its WireGuard session keys. So the
// first packet after a sign-in starts a new handshake at once, instead of
// the old keys being tried until WireGuard gives up on them.
func (t *Tunnel) Up(cfg *protocol.TunnelConfig, priv, psk protocol.Key) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.adapter != nil {
		return errors.New("tunnel already up")
	}
	endpoint, err := resolve(cfg.EndpointHost, cfg.EndpointPort)
	if err != nil {
		return err
	}
	adapter, err := driver.CreateAdapter(AdapterName, tunnelType, &adapterGUID)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		// Left from an earlier run that did not end cleanly.
		if old, oerr := driver.OpenAdapter(AdapterName); oerr == nil {
			old.Close()
		}
		adapter, err = driver.CreateAdapter(AdapterName, tunnelType, &adapterGUID)
	}
	if err != nil {
		return fmt.Errorf("creating the adapter: %w", err)
	}
	t.adapter, t.luid = adapter, adapter.LUID()
	t.priv, t.psk, t.peer, t.endpoint, t.host = priv, psk, cfg.ServerPublicKey, endpoint, cfg.EndpointHost
	plan := NewPlan(cfg)
	if err := t.bringUp(cfg, plan); err != nil {
		t.downLocked()
		return err
	}
	t.plan = plan
	return nil
}

func (t *Tunnel) bringUp(cfg *protocol.TunnelConfig, plan *Plan) error {
	if v, err := driver.RunningVersion(); err == nil {
		t.log("WireGuardNT driver", "version", v, "dll", driver.Version())
	}
	if err := t.adapter.SetLogging(driver.AdapterLogOn); err != nil {
		t.log("adapter logging could not be enabled", "err", err)
	}
	if err := t.setPeer(cfg, true); err != nil {
		return err
	}
	if err := t.adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return fmt.Errorf("bringing the adapter up: %w", err)
	}
	if err := t.configureInterface(plan); err != nil {
		return err
	}
	return t.configureDNS(plan)
}

// setPeer writes the WireGuard configuration. With replace, the interface
// key and the whole peer are set; otherwise the existing peer is updated.
func (t *Tunnel) setPeer(cfg *protocol.TunnelConfig, replace bool) error {
	iface := driver.Interface{PeerCount: 1}
	peer := driver.Peer{
		Flags:           driver.PeerHasPublicKey | driver.PeerHasEndpoint | driver.PeerReplaceAllowedIPs,
		PublicKey:       cfg.ServerPublicKey,
		AllowedIPsCount: uint32(len(cfg.AllowedIPs)),
	}
	if replace {
		iface.Flags = driver.InterfaceHasPrivateKey | driver.InterfaceReplacePeers
		iface.PrivateKey = t.priv
		peer.Flags |= driver.PeerHasPresharedKey
		peer.PresharedKey = t.psk
	} else {
		peer.Flags |= driver.PeerUpdateOnly
	}
	// No PersistentKeepalive, ever: the server detects idle sessions by the
	// tunnel's silence (section 8).
	if err := peer.Endpoint.SetAddrPort(t.endpoint); err != nil {
		return err
	}
	var b driver.ConfigBuilder
	b.Preallocate(uint32(1024 + 64*len(cfg.AllowedIPs)))
	b.AppendInterface(&iface)
	b.AppendPeer(&peer)
	for _, p := range cfg.AllowedIPs {
		a := driver.AllowedIP{Cidr: uint8(p.Bits())}
		if p.Addr().Is4() {
			a.AddressFamily = windows.AF_INET
			v4 := p.Addr().As4()
			copy(a.Address[:], v4[:])
		} else {
			a.AddressFamily = windows.AF_INET6
			a.Address = p.Addr().As16()
		}
		b.AppendAllowedIP(&a)
	}
	conf, size := b.Interface()
	err := t.adapter.SetConfiguration(conf, size)
	clear(iface.PrivateKey[:])
	clear(peer.PresharedKey[:])
	if err != nil {
		return fmt.Errorf("configuring WireGuard: %w", err)
	}
	return nil
}

// configureInterface sets the address, routes, MTU and metric, retrying
// while the adapter's IP interfaces are still being created.
func (t *Tunnel) configureInterface(plan *Plan) error {
	var err error
	for range interfaceRetries {
		if err = t.configureFamilies(plan); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return err
		}
		time.Sleep(interfaceRetry)
	}
	return err
}

func (t *Tunnel) configureFamilies(plan *Plan) error {
	for _, f := range []struct {
		family winipcfg.AddressFamily
		routes []netip.Prefix
		is4    bool
		full   bool
	}{
		{windows.AF_INET, plan.Routes4, true, plan.Full4},
		{windows.AF_INET6, plan.Routes6, false, plan.Full6},
	} {
		var addrs []netip.Prefix
		if plan.Address.Addr().Is4() == f.is4 {
			addrs = []netip.Prefix{plan.Address}
		}
		if len(addrs) == 0 && len(f.routes) == 0 {
			// Nothing of this family; clear what an earlier configuration set.
			if t.plan != nil {
				t.luid.SetRoutesForFamily(f.family, nil)
				t.luid.FlushIPAddresses(f.family)
			}
			continue
		}
		routes := make([]*winipcfg.RouteData, len(f.routes))
		for i, r := range f.routes {
			next := netip.IPv6Unspecified()
			if f.is4 {
				next = netip.IPv4Unspecified()
			}
			routes[i] = &winipcfg.RouteData{Destination: r, NextHop: next}
		}
		if err := t.luid.SetIPAddressesForFamily(f.family, addrs); err != nil {
			return fmt.Errorf("setting the tunnel address: %w", err)
		}
		if err := t.luid.SetRoutesForFamily(f.family, routes); err != nil {
			return fmt.Errorf("setting routes: %w", err)
		}
		ipif, err := t.luid.IPInterface(f.family)
		if err != nil {
			return err
		}
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.DadTransmits = 0
		ipif.ManagedAddressConfigurationSupported = false
		ipif.OtherStatefulConfigurationSupported = false
		ipif.NLMTU = uint32(plan.MTU)
		ipif.UseAutomaticMetric = !f.full
		if f.full {
			ipif.Metric = 0
		}
		if err := ipif.Set(); err != nil {
			return fmt.Errorf("setting MTU and metric: %w", err)
		}
	}
	return nil
}

// configureDNS sets the interface DNS and Hifaz's NRPT rule.
func (t *Tunnel) configureDNS(plan *Plan) error {
	defer notifyDNS()
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		err := t.luid.SetDNS(family, plan.InterfaceDNS, plan.SearchDomains)
		if err != nil && (family == windows.AF_INET || hasIPv6(plan.InterfaceDNS)) {
			return fmt.Errorf("setting DNS: %w", err)
		}
	}
	if plan.Rule == nil {
		return removeRule()
	}
	if GroupPolicyNRPT() {
		t.log("Group Policy sets DNS name rules, so Windows ignores Hifaz's rule; names may not resolve through Hifaz DNS")
	}
	if len(plan.DNSOutsideTunnel) > 0 {
		t.log("DNS server is outside the tunnel's routes; while connected every name lookup goes to it, so if it cannot be reached outside the tunnel, names will not resolve", "servers", plan.DNSOutsideTunnel)
	}
	if err := setRule(plan.Rule); err != nil {
		return fmt.Errorf("setting the DNS rule: %w", err)
	}
	return nil
}

func hasIPv6(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if a.Is6() {
			return true
		}
	}
	return false
}

// Reconfigure implements daemon.Tunnel.
func (t *Tunnel) Reconfigure(cfg *protocol.TunnelConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.adapter == nil {
		return errors.New("tunnel not up")
	}
	switch {
	case cfg.EndpointHost == t.host && cfg.EndpointPort != t.endpoint.Port():
		// Only the port changed: keep the address. A lookup now would go
		// to the server's DNS through the tunnel.
		t.endpoint = netip.AddrPortFrom(t.endpoint.Addr(), cfg.EndpointPort)
	case cfg.EndpointHost != t.host:
		endpoint, err := resolve(cfg.EndpointHost, cfg.EndpointPort)
		if err != nil {
			return err
		}
		if EndpointInside(endpoint.Addr(), cfg.AllowedIPs) {
			// The server's DNS gave an address only reachable through the
			// tunnel; the driver does not send the encrypted packets into
			// its own interface, so the tunnel would stop working. t.host
			// stays, so the next configuration tries again.
			t.log("new endpoint resolves inside the tunnel; keeping the current one", "host", cfg.EndpointHost,
				"address", endpoint.Addr(), "reason", "only reachable through the tunnel itself")
		} else {
			t.endpoint, t.host = endpoint, cfg.EndpointHost
		}
	}
	replace := cfg.ServerPublicKey != t.peer
	if err := t.setPeer(cfg, replace); err != nil {
		return err
	}
	t.peer = cfg.ServerPublicKey
	plan := NewPlan(cfg)
	if err := t.configureInterface(plan); err != nil {
		return err
	}
	if err := t.configureDNS(plan); err != nil {
		return err
	}
	t.plan = plan
	return nil
}

// Down implements daemon.Tunnel.
func (t *Tunnel) Down() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.downLocked()
}

func (t *Tunnel) downLocked() error {
	err := removeRule()
	if t.adapter != nil {
		// Clear the interface DNS first, so nothing of it stays in the
		// registry. IPv6 may be off on the machine: its error is ignored.
		for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
			if derr := t.luid.SetDNS(family, nil, nil); derr != nil && family == windows.AF_INET && err == nil {
				err = fmt.Errorf("clearing DNS: %w", derr)
			}
		}
		// Closing the adapter removes it, with its address and routes.
		if cerr := t.adapter.Close(); err == nil {
			err = cerr
		}
		t.adapter = nil
		notifyDNS()
	}
	t.priv.Wipe()
	t.psk.Wipe()
	t.plan = nil
	return err
}

// Stats implements daemon.Tunnel.
func (t *Tunnel) Stats() (daemon.Stats, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.adapter == nil {
		return daemon.Stats{}, errors.New("tunnel not up")
	}
	conf, err := t.adapter.Configuration()
	if err != nil {
		return daemon.Stats{}, err
	}
	if conf.PeerCount == 0 {
		return daemon.Stats{}, nil
	}
	p := conf.FirstPeer()
	st := daemon.Stats{RxBytes: p.RxBytes, TxBytes: p.TxBytes}
	if p.LastHandshake != 0 {
		// 100 ns intervals since 1601-01-01 UTC.
		st.LastHandshake = time.Unix(0, (int64(p.LastHandshake)-116444736000000000)*100).UTC()
	}
	return st, nil
}

// Cleanup removes anything a previous run may have left: Hifaz's DNS rule
// and adapter. It runs when the service starts and when Hifaz is removed.
func Cleanup() error {
	err := removeRule()
	if a, oerr := driver.OpenAdapter(AdapterName); oerr == nil {
		a.Close()
	}
	notifyDNS()
	return err
}

func resolve(host string, port uint16) (netip.AddrPort, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(a, port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolving %s: %w", net.JoinHostPort(host, strconv.Itoa(int(port))), err)
	}
	for _, a := range addrs { // prefer IPv4, which every network has
		if a.Unmap().Is4() {
			return netip.AddrPortFrom(a.Unmap(), port), nil
		}
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolving %s: no address", host)
	}
	return netip.AddrPortFrom(addrs[0], port), nil
}

// RemoveDriverIfUnused removes the WireGuardNT driver when no adapter, of
// Hifaz or of any other program, is using it. The official WireGuard app
// installs it again by itself when it next needs it.
func RemoveDriverIfUnused() error {
	return driver.Uninstall()
}
