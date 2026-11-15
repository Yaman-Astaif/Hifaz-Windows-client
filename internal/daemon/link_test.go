package daemon

import (
	"testing"
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
)

var t0 = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

// linkRun drives a link second by second, as Engine.Run does.
type linkRun struct {
	t   *testing.T
	l   *link
	now time.Time
	st  Stats
}

func newLinkRun(t *testing.T) *linkRun {
	return &linkRun{t: t, l: newLink(t0), now: t0}
}

// tick advances one second and steps, applying DNS actions as the engine
// does when SetDNS works.
func (r *linkRun) tick() actions {
	r.now = r.now.Add(linkPoll)
	a := r.l.step(r.st, r.now)
	if a.dnsOn {
		r.l.dnsOn = true
	}
	if a.dnsOff {
		r.l.dnsOn = false
	}
	return a
}

// until ticks until d after t0 has passed, returning the counted actions.
func (r *linkRun) until(d time.Duration) (probes, checks int) {
	for r.now.Before(t0.Add(d)) {
		a := r.tick()
		if a.probe {
			probes++
		}
		if a.checkBlocker {
			checks++
		}
	}
	return
}

func (r *linkRun) want(s ipc.Link, dns bool) {
	r.t.Helper()
	if r.l.state != s || r.l.dnsOn != dns {
		r.t.Fatalf("at %v: %s dns=%v, want %s dns=%v", r.now.Sub(t0), r.l.state, r.l.dnsOn, s, dns)
	}
}

func TestLinkFirstAnswerTimeout(t *testing.T) {
	r := newLinkRun(t)
	r.until(9 * time.Second)
	r.want(ipc.LinkWaiting, false)
	a := r.tick() // 10 s
	r.want(ipc.LinkNoAnswer, false)
	if !a.changed || !a.checkBlocker || a.dnsOff {
		t.Fatalf("at 10 s: %+v", a)
	}
}

func TestLinkHandshakeBringsDNS(t *testing.T) {
	r := newLinkRun(t)
	r.until(3 * time.Second)
	r.st.LastHandshake = r.now
	a := r.tick()
	r.want(ipc.LinkUp, true)
	if !a.changed || !a.dnsOn || a.probe || a.checkBlocker {
		t.Fatalf("%+v", a)
	}
	// Up while the handshake is fresh: no more actions.
	r.st.TxBytes = 1000
	for range 30 {
		if a := r.tick(); a != (actions{}) {
			t.Fatalf("at %v: %+v", r.now.Sub(t0), a)
		}
	}
}

func TestLinkIdleStaysUpWithoutProbes(t *testing.T) {
	r := newLinkRun(t)
	r.st = Stats{LastHandshake: t0, TxBytes: 500}
	r.tick()
	r.want(ipc.LinkUp, true)
	// An hour with nothing sent: the handshake grows old, nothing changes,
	// nothing is sent.
	if probes, checks := r.until(time.Hour); probes != 0 || checks != 0 {
		t.Fatalf("%d probes, %d checks while idle", probes, checks)
	}
	r.want(ipc.LinkUp, true)
}

func TestLinkLost(t *testing.T) {
	r := newLinkRun(t)
	r.st = Stats{LastHandshake: t0, TxBytes: 500}
	r.tick()
	r.until(handshakeLost + time.Minute) // idle, handshake old
	r.want(ipc.LinkUp, true)
	r.st.TxBytes += 100 // sending starts
	r.tick()
	start := r.now
	for r.now.Sub(start) < 14*time.Second {
		r.st.TxBytes += 100
		r.tick()
	}
	r.want(ipc.LinkUp, true) // 14 s
	r.st.TxBytes += 100
	a := r.tick() // 15 s
	r.want(ipc.LinkNoAnswer, false)
	if !a.changed || !a.dnsOff || !a.checkBlocker || !a.probe {
		t.Fatalf("lost: %+v", a)
	}
	// The server answers again: DNS back, blocker cleared.
	r.l.blocker = &ipc.Blocker{App: ipc.BlockerWireGuard}
	r.st.LastHandshake = r.now
	a = r.tick()
	r.want(ipc.LinkUp, true)
	if !a.changed || !a.dnsOn || r.l.blocker != nil {
		t.Fatalf("back: %+v, blocker %+v", a, r.l.blocker)
	}
}

func TestLinkRekeyWhileSending(t *testing.T) {
	r := newLinkRun(t)
	r.st = Stats{LastHandshake: t0, TxBytes: 500}
	r.tick()
	r.until(handshakeLost + time.Minute)
	r.st.TxBytes += 100
	r.tick()
	r.until(handshakeLost + time.Minute + 10*time.Second)
	r.st.LastHandshake = r.now // the handshake comes through in time
	r.tick()
	// Sending again later, with a fresh handshake, is no loss either; and
	// the earlier sending does not count once the handshake went old again.
	r.until(2*handshakeLost + 2*time.Minute)
	r.st.TxBytes += 100
	r.tick()
	r.until(2*handshakeLost + 2*time.Minute + 10*time.Second)
	r.want(ipc.LinkUp, true)
}

func TestLinkNoAnswerRetries(t *testing.T) {
	r := newLinkRun(t)
	r.l.lastProbe = t0 // the engine probes at sign-in
	probes, checks := r.until(firstAnswerTimeout + 5*time.Minute)
	r.want(ipc.LinkNoAnswer, false)
	// One probe every probeRetry, the blocker every blockerRecheck.
	wantProbes := int((firstAnswerTimeout + 5*time.Minute) / probeRetry)
	wantChecks := 1 + int(5*time.Minute/blockerRecheck)
	if probes != wantProbes || checks != wantChecks {
		t.Fatalf("%d probes (want %d), %d checks (want %d)", probes, wantProbes, checks, wantChecks)
	}
}

func TestLinkStaleHandshakeIsNotAnAnswer(t *testing.T) {
	// After the server key changed the engine waits again; an old
	// handshake does not count as an answer.
	r := newLinkRun(t)
	r.st.LastHandshake = t0.Add(-handshakeLost - time.Second)
	r.tick()
	r.want(ipc.LinkWaiting, false)
}

func TestLinkWaitingKeepsDNS(t *testing.T) {
	r := newLinkRun(t)
	r.l.dnsOn = true // waiting again after a new server key
	r.until(9 * time.Second)
	r.want(ipc.LinkWaiting, true)
	r.tick()
	r.want(ipc.LinkNoAnswer, false)
}

func TestLinkRetriesDNS(t *testing.T) {
	r := newLinkRun(t)
	r.l.state, r.l.dnsOn = ipc.LinkUp, false // SetDNS(true) did not work
	r.st.LastHandshake = t0
	if a := r.l.step(r.st, t0.Add(time.Second)); !a.dnsOn || a.changed {
		t.Fatalf("%+v", a)
	}
	r.l.state, r.l.dnsOn = ipc.LinkNoAnswer, true // SetDNS(false) did not work
	r.st.LastHandshake = time.Time{}
	if a := r.l.step(r.st, t0.Add(2*time.Second)); !a.dnsOff || a.changed {
		t.Fatalf("%+v", a)
	}
}
