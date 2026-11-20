package tunnel

import (
	"fmt"
	"net/netip"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/protocol"
)

func selectEndpoint(host string, port uint16, addrs []netip.Addr) (netip.AddrPort, error) {
	var ipv6 netip.Addr
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !protocol.UsableUnicast(addr) {
			continue
		}
		if addr.Is4() {
			return netip.AddrPortFrom(addr, port), nil
		}
		if !ipv6.IsValid() {
			ipv6 = addr
		}
	}
	if ipv6.IsValid() {
		return netip.AddrPortFrom(ipv6, port), nil
	}
	return netip.AddrPort{}, fmt.Errorf("resolving %s: no usable address", host)
}
