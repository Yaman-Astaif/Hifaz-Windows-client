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

func TestDPIChanged(t *testing.T) {
	const fw, fh = 9, 45 // the frame at 144 DPI
	w, h := int32(690+fw), int32(1020+fh)

	// Room enough: the suggested place, the fixed size for the new DPI.
	work := rect{Left: 1920, Top: 0, Right: 1920 + 2560, Bottom: 1400}
	suggested := rect{Left: 2000, Top: 100, Right: 2000 + 700, Bottom: 100 + 1000}
	if r, want := dpiChanged(suggested, 144, fw, fh, work, false), (rect{Left: 2000, Top: 100, Right: 2000 + w, Bottom: 100 + h}); r != want {
		t.Errorf("room enough: %+v, want %+v", r, want)
	}

	// 100% to a 1080p monitor at 150% (work area 1032 high): the suggested
	// size would be taller than the work area; the window is clamped to it
	// and moved up into it.
	work = rect{Left: 1920, Right: 3840, Bottom: 1032}
	suggested = rect{Left: 2100, Top: 150, Right: 2100 + w, Bottom: 150 + h}
	r := dpiChanged(suggested, 144, fw, fh, work, false)
	if r.Top != 0 || r.Bottom != 1032 || r.Left != 2100 || r.Right-r.Left != w {
		t.Errorf("clamped: %+v", r)
	}

	// Past the work area's right and bottom edges: moved back inside.
	work = rect{Left: 1920, Top: 40, Right: 3840, Bottom: 1440}
	suggested = rect{Left: 3500, Top: 600, Right: 3500 + w, Bottom: 600 + h}
	r = dpiChanged(suggested, 144, fw, fh, work, false)
	if r.Right != 3840 || r.Bottom != 1440 || r.Right-r.Left != w || r.Bottom-r.Top != h {
		t.Errorf("moved inside: %+v", r)
	}
	// And past the left and top edges.
	suggested = rect{Left: 1800, Top: 0, Right: 1800 + w, Bottom: h}
	if r = dpiChanged(suggested, 144, fw, fh, work, false); r.Left != 1920 || r.Top != 40 {
		t.Errorf("moved inside, top left: %+v", r)
	}

	// Keep the cursor-relative position during a cross-monitor drag, even
	// if the fixed size needs to shrink to the destination work area.
	work = rect{Left: 1920, Top: 40, Right: 3840, Bottom: 1048}
	if r = dpiChanged(suggested, 144, fw, fh, work, true); r.Left != suggested.Left ||
		r.Top != suggested.Top || r.Right-r.Left != w || r.Bottom-r.Top != 1008 {
		t.Errorf("during drag: %+v", r)
	}

	// No work area known: the suggested place, the full size.
	suggested = rect{Left: 10, Top: 20, Right: 500, Bottom: 600}
	if r = dpiChanged(suggested, 96, 6, 29, rect{}, false); r != (rect{Left: 10, Top: 20, Right: 10 + 466, Bottom: 20 + 709}) {
		t.Errorf("no work area: %+v", r)
	}
}
