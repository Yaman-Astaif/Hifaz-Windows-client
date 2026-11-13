package protocol

import (
	"context"
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
)

// fakeConn is a connection that reports a given remote address.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (c fakeConn) RemoteAddr() net.Addr { return c.remote }
func (c fakeConn) Close() error         { return nil }

// fakeNet answers dials: names resolve to ip, or fail when ip is empty;
// literal addresses always connect.
type fakeNet struct {
	mu    sync.Mutex
	ip    string
	dials []string
}

func (n *fakeNet) set(ip string) { n.mu.Lock(); n.ip = ip; n.mu.Unlock() }

func (n *fakeNet) dial(_ context.Context, _, addr string) (net.Conn, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dials = append(n.dials, addr)
	host, port, _ := net.SplitHostPort(addr)
	if net.ParseIP(host) == nil {
		if n.ip == "" {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "timeout", Name: host, IsTimeout: true}}
		}
		host = n.ip
	}
	tcp, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	return fakeConn{remote: tcp}, nil
}

func (n *fakeNet) lastDial() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.dials[len(n.dials)-1]
}

func dialTo(t *testing.T, d *rememberingDialer, addr string) (string, error) {
	t.Helper()
	conn, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		return "", err
	}
	return conn.RemoteAddr().String(), nil
}

func TestDialerUsesRememberedAddressWhenLookupFails(t *testing.T) {
	n := &fakeNet{ip: "192.0.2.10"}
	d := newRememberingDialer(n.dial)
	if got, err := dialTo(t, d, "hifaz.example.com:443"); err != nil || got != "192.0.2.10:443" {
		t.Fatalf("first dial %q %v", got, err)
	}
	n.set("") // the tunnel's DNS no longer answers
	got, err := dialTo(t, d, "hifaz.example.com:443")
	if err != nil || got != "192.0.2.10:443" || n.lastDial() != "192.0.2.10:443" {
		t.Fatalf("after a failed lookup: %q %v, dialed %s", got, err, n.lastDial())
	}
}

func TestDialerLookupFailsWithNothingRemembered(t *testing.T) {
	n := &fakeNet{}
	d := newRememberingDialer(n.dial)
	_, err := dialTo(t, d, "hifaz.example.com:443")
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		t.Fatalf("error %v", err)
	}
	if len(n.dials) != 1 {
		t.Fatalf("dials %v", n.dials)
	}
	// Another port of the same host is a different entry.
	n.set("192.0.2.10")
	dialTo(t, d, "hifaz.example.com:443")
	n.set("")
	if _, err := dialTo(t, d, "hifaz.example.com:8443"); err == nil {
		t.Fatal("dialed a port that was never reached")
	}
}

// The first address reached is kept: later dials may run while the tunnel
// is up, when the server's DNS can answer with an address inside it.
func TestDialerKeepsFirstAddress(t *testing.T) {
	n := &fakeNet{ip: "192.0.2.10"}
	d := newRememberingDialer(n.dial)
	if got, err := dialTo(t, d, "hifaz.example.com:443"); err != nil || got != "192.0.2.10:443" {
		t.Fatalf("first dial %q %v", got, err)
	}
	n.set("10.98.0.1") // the tunnel's DNS answers privately
	if got, err := dialTo(t, d, "hifaz.example.com:443"); err != nil || got != "10.98.0.1:443" {
		t.Fatalf("dial while connected %q %v", got, err)
	}
	n.set("")
	got, err := dialTo(t, d, "hifaz.example.com:443")
	if err != nil || got != "192.0.2.10:443" || n.lastDial() != "192.0.2.10:443" {
		t.Fatalf("after a failed lookup: %q %v, dialed %s", got, err, n.lastDial())
	}
}

func TestDialerEachPortKeepsItsOwnFirstAddress(t *testing.T) {
	n := &fakeNet{ip: "192.0.2.10"}
	d := newRememberingDialer(n.dial)
	dialTo(t, d, "hifaz.example.com:443")
	n.set("192.0.2.11")
	dialTo(t, d, "hifaz.example.com:8443")
	n.set("10.98.0.1")
	dialTo(t, d, "hifaz.example.com:443")
	dialTo(t, d, "hifaz.example.com:8443")
	n.set("")
	if got, err := dialTo(t, d, "hifaz.example.com:443"); err != nil || got != "192.0.2.10:443" {
		t.Fatalf("port 443: %q %v", got, err)
	}
	if got, err := dialTo(t, d, "hifaz.example.com:8443"); err != nil || got != "192.0.2.11:8443" {
		t.Fatalf("port 8443: %q %v", got, err)
	}
}

func TestDialerOtherErrorsAreNotRetried(t *testing.T) {
	n := &fakeNet{ip: "192.0.2.10"}
	calls := 0
	refuse := func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return n.dial(ctx, network, addr)
		}
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
	}
	d := newRememberingDialer(refuse)
	dialTo(t, d, "hifaz.example.com:443")
	if _, err := dialTo(t, d, "hifaz.example.com:443"); err == nil || calls != 2 {
		t.Fatalf("err %v, %d calls", err, calls)
	}
}

func TestDialerLiteralAddress(t *testing.T) {
	n := &fakeNet{}
	d := newRememberingDialer(n.dial)
	if got, err := dialTo(t, d, "192.0.2.20:443"); err != nil || got != "192.0.2.20:443" {
		t.Fatalf("%q %v", got, err)
	}
	if len(d.last) != 0 {
		t.Fatalf("remembered %v", d.last)
	}
}

func TestDialerConcurrent(t *testing.T) {
	n := &fakeNet{ip: "192.0.2.10"}
	d := newRememberingDialer(n.dial)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				n.set("")
			} else {
				n.set("192.0.2.10")
			}
			dialTo(t, d, "hifaz.example.com:443")
		}()
	}
	wg.Wait()
}
