package winui

import "testing"

func TestScale(t *testing.T) {
	for _, c := range []struct {
		v, dpi int
		want   int32
	}{{460, 96, 460}, {460, 120, 575}, {760, 144, 1140}, {680, 144, 1020}, {400, 192, 800}} {
		if got := scale(c.v, c.dpi); got != c.want {
			t.Errorf("scale(%d, %d) = %d, want %d", c.v, c.dpi, got, c.want)
		}
	}
}

func TestPlacement(t *testing.T) {
	const fw, fh = 6, 29 // the fixed window's frame at 96 DPI
	centred := func(work rect, w, h int32) rect {
		x := work.Left + (work.Right-work.Left-w)/2
		y := work.Top + (work.Bottom-work.Top-h)/2
		return rect{Left: x, Top: y, Right: x + w, Bottom: y + h}
	}

	// 96 DPI, 1920x1040 work area: the full size, centred.
	work := rect{Right: 1920, Bottom: 1040}
	if r, want := placement(96, fw, fh, work), centred(work, 460+fw, 680+fh); r != want {
		t.Errorf("96 DPI: %+v, want %+v", r, want)
	}

	// 1366x768 at 100% (work area 1366x728): still the full size, centred.
	work = rect{Right: 1366, Bottom: 728}
	if r, want := placement(96, fw, fh, work), centred(work, 460+fw, 680+fh); r != want {
		t.Errorf("1366x768: %+v, want %+v", r, want)
	}

	// 144 DPI on 1920x1032: too tall, so as tall as the work area, at its top.
	r := placement(144, fw, fh, rect{Right: 1920, Bottom: 1032})
	w := int32(690 + fw)
	if r.Top != 0 || r.Bottom != 1032 || r.Right-r.Left != w || r.Left != (1920-w)/2 {
		t.Errorf("144 DPI on 1032: %+v", r)
	}

	// 1920x1080 at 150% with a taller taskbar (work area 1008): clamped too.
	r = placement(144, fw, fh, rect{Right: 1920, Bottom: 1008})
	if r.Top != 0 || r.Bottom != 1008 || r.Right-r.Left != w || r.Left != (1920-w)/2 {
		t.Errorf("144 DPI on 1008: %+v", r)
	}

	// A second monitor to the right, its work area below a top taskbar.
	work = rect{Left: 1920, Top: 40, Right: 3840, Bottom: 1080}
	if r, want := placement(96, fw, fh, work), centred(work, 460+fw, 680+fh); r != want {
		t.Errorf("second monitor: %+v, want %+v", r, want)
	}

	// No work area known: the full size at the origin.
	if r = placement(96, fw, fh, rect{}); r != (rect{Right: 460 + fw, Bottom: 680 + fh}) {
		t.Errorf("no work area: %+v", r)
	}
}

func TestAllowSysCommand(t *testing.T) {
	// The low four bits are Windows' own; 0xF032 is SC_MAXIMIZE from a
	// title-bar double-click, 0xF008 a bottom-right edge SC_SIZE.
	for _, c := range []uintptr{0xF030, 0xF032, 0xF000, 0xF008} {
		if allowSysCommand(c) {
			t.Errorf("allowSysCommand(%#x) = true, want false", c)
		}
	}
	// Minimize, close, move (menu and drag), restore, the window menu (Alt+Space).
	for _, c := range []uintptr{0xF020, 0xF060, 0xF010, 0xF012, 0xF120, 0xF100} {
		if !allowSysCommand(c) {
			t.Errorf("allowSysCommand(%#x) = false, want true", c)
		}
	}
}
