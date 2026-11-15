package daemon

import (
	"time"

	"github.com/Yaman-Astaif/Hifaz-Windows-client/internal/ipc"
)

// Whether the server answers through the tunnel, from WireGuard's handshake
// time and the bytes sent. Nothing is sent to keep the session alive
// (protocol section 8: the server counts idle time from what it receives,
// handshake initiations included): a probe packet goes into the tunnel, to
// start a handshake, only for probeWindow after sign-in, after a new server
// key, or after the link went from up to no answer. After that only the
// user's own traffic makes WireGuard try again, so a session whose
// handshake never completes still goes idle on the server. A blocker found
// in the episode going away (a real change in another app's firewall, never
// a timer) starts one more window.
//
// LastHandshake is wall-clock time: a forward clock jump of more than
// handshakeLost while sending can briefly show no answer, until the next
// rekey (within about 2 minutes).
const (
	linkPoll           = time.Second      // how often Run looks
	firstAnswerTimeout = 10 * time.Second // after sign-in, before "no answer"
	// WireGuard keeps a session's keys for 3 minutes (Reject-After-Time);
	// with traffic flowing it makes a new handshake before then.
	handshakeLost = 3 * time.Minute
	// Sending with an old handshake: WireGuard handshakes at once. This
	// long without one, the server does not answer.
	lostGrace  = 15 * time.Second
	probeRetry = 10 * time.Second
	// WireGuard itself gives up retrying a handshake after 90 seconds
	// (Rekey-Attempt-Time); probing stops then too.
	probeWindow    = 90 * time.Second
	blockerRecheck = time.Minute
)

// link is the owner's link state. Invariants: up means DNS is on (retried
// on each step until it is); no answer means DNS is off; waiting leaves DNS
// as it is (off at sign-in).
type link struct {
	state ipc.Link
	since time.Time // when waiting started
	// lastTx is the TxBytes of the previous step. sendingSince is the first
	// step that saw TxBytes grow after the handshake went old.
	lastTx           uint64
	sendingSince     time.Time
	lastProbe        time.Time
	probeArmed       time.Time // start of the current probe window
	lastBlockerCheck time.Time
	dnsOn            bool
	blocker          *ipc.Blocker
	// The last errors logged, so a failure repeating every second is
	// logged once: probeErr per probe window, dnsErr until DNS is removed.
	probeErr, dnsErr string
	// blockerSeen: a lookup in this no-answer episode found a blocker.
	blockerSeen bool
}

// actions are what the engine does after a step.
type actions struct {
	probe        bool // send one probe packet into the tunnel
	dnsOn        bool // apply Hifaz DNS
	dnsOff       bool // remove Hifaz DNS
	checkBlocker bool // look for what keeps the server from answering
	changed      bool // the state changed
}

// newLink starts waiting for the first answer at now; the engine sends the
// first probe at the same time.
func newLink(now time.Time) *link {
	return &link{state: ipc.LinkWaiting, since: now, lastProbe: now, probeArmed: now}
}

// wait starts waiting again (a new server key resets the handshake).
func (l *link) wait(now time.Time) {
	l.state, l.since, l.lastProbe, l.probeArmed, l.probeErr = ipc.LinkWaiting, now, now, now, ""
	l.sendingSince, l.blocker, l.blockerSeen = time.Time{}, nil, false
}

// blockerFound records a successful lookup's result. When a blocker found
// earlier in this episode is gone (the user turned the other VPN's kill
// switch off), a new probe window starts: with DNS off nothing else would
// make WireGuard handshake. It reports whether it re-armed.
func (l *link) blockerFound(b *ipc.Blocker, now time.Time) bool {
	if b != nil {
		l.blockerSeen = true
		return false
	}
	if !l.blockerSeen {
		return false
	}
	l.blockerSeen = false
	l.probeArmed, l.probeErr = now, ""
	return true
}

// step moves the state on from the tunnel's counters at now.
func (l *link) step(st Stats, now time.Time) actions {
	var a actions
	fresh := !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) < handshakeLost
	grew := st.TxBytes > l.lastTx
	l.lastTx = st.TxBytes
	before := l.state

	switch l.state {
	case ipc.LinkUp:
		switch {
		case fresh:
			l.sendingSince = time.Time{}
		case grew && l.sendingSince.IsZero():
			l.sendingSince = now
		}
		if !l.sendingSince.IsZero() && now.Sub(l.sendingSince) >= lostGrace {
			l.noAnswer(now, &a)
			l.probeArmed, l.probeErr, l.dnsErr = now, "", "" // a new episode
		}
	case ipc.LinkWaiting:
		if fresh {
			l.up()
		} else if now.Sub(l.since) >= firstAnswerTimeout {
			l.noAnswer(now, &a)
		}
	case ipc.LinkNoAnswer:
		if fresh {
			l.up()
		} else if now.Sub(l.lastBlockerCheck) >= blockerRecheck {
			l.lastBlockerCheck = now
			a.checkBlocker = true
		}
	}

	if l.state != ipc.LinkUp && now.Sub(l.probeArmed) < probeWindow && now.Sub(l.lastProbe) >= probeRetry {
		l.lastProbe = now
		a.probe = true
	}
	a.dnsOn = l.state == ipc.LinkUp && !l.dnsOn
	a.dnsOff = l.state == ipc.LinkNoAnswer && l.dnsOn
	a.changed = l.state != before
	return a
}

func (l *link) up() {
	l.state, l.sendingSince, l.blocker, l.blockerSeen = ipc.LinkUp, time.Time{}, nil, false
}

func (l *link) noAnswer(now time.Time, a *actions) {
	l.state, l.sendingSince, l.lastBlockerCheck = ipc.LinkNoAnswer, time.Time{}, now
	a.checkBlocker = true
}
