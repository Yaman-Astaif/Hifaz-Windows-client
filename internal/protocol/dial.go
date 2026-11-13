package protocol

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
)

// rememberingDialer dials by host name and remembers, per host and port,
// the first address it reached. When a later name lookup fails, it dials
// that address instead.
//
// While a tunnel is up, all DNS goes to the server's DNS through the tunnel.
// If the server has dropped the peer (the computer slept past the idle or
// time limit), no name resolves any more, and without this the app could
// never ask the server that the session has ended, so the tunnel and its
// DNS would stay.
//
// Only the first address is kept. A client is built for each sign-in and
// its first dial is made before the tunnel is up, so an answer from the
// server's DNS (which may be a private address inside the tunnel) is never
// remembered. Callers must not reuse a client across sign-ins.
//
// Only the TCP target changes: TLS still checks the certificate for the
// host name and sends it as SNI, as the transport takes both from the
// request, not from the dialed address.
type rememberingDialer struct {
	dial func(ctx context.Context, network, addr string) (net.Conn, error)

	mu   sync.Mutex
	last map[string]netip.Addr // "host:port" -> first address reached
}

func newRememberingDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *rememberingDialer {
	return &rememberingDialer{dial: dial, last: map[string]netip.Addr{}}
}

// DialContext is the transport's DialContext.
func (d *rememberingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return d.dial(ctx, network, addr)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return d.dial(ctx, network, addr) // a literal address: nothing to resolve
	}
	conn, err := d.dial(ctx, network, addr)
	if err == nil {
		if ap, perr := netip.ParseAddrPort(conn.RemoteAddr().String()); perr == nil {
			d.mu.Lock()
			if _, ok := d.last[addr]; !ok {
				d.last[addr] = ap.Addr().Unmap()
			}
			d.mu.Unlock()
		}
		return conn, nil
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return nil, err
	}
	d.mu.Lock()
	ip, ok := d.last[addr]
	d.mu.Unlock()
	if !ok {
		return nil, err
	}
	return d.dial(ctx, network, net.JoinHostPort(ip.String(), port))
}
