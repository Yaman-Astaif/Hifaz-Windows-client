package winui

import "testing"

func TestScale(t *testing.T) {
	for _, c := range []struct {
		v, dpi int
		want   int32
	}{{460, 96, 460}, {460, 120, 575}, {760, 144, 1140}, {400, 192, 800}} {
		if got := scale(c.v, c.dpi); got != c.want {
			t.Errorf("scale(%d, %d) = %d, want %d", c.v, c.dpi, got, c.want)
		}
	}
}

func TestMinTrackSize(t *testing.T) {
	const fw, fh = 16, 39
	big := rect{Right: 3840, Bottom: 2100}
	if w, h := minTrackSize(96, fw, fh, big); w != 400+fw || h != 560+fh {
		t.Errorf("96 DPI: %dx%d", w, h)
	}
	if w, h := minTrackSize(144, fw, fh, big); w != 600+fw || h != 840+fh {
		t.Errorf("144 DPI: %dx%d", w, h)
	}
	// A work area smaller than the minimum caps it, so the window always fits.
	small := rect{Left: 100, Top: 50, Right: 500, Bottom: 550}
	if w, h := minTrackSize(144, fw, fh, small); w != 400 || h != 500 {
		t.Errorf("small work area: %dx%d", w, h)
	}
	// No work area known: no cap.
	if w, h := minTrackSize(96, fw, fh, rect{}); w != 400+fw || h != 560+fh {
		t.Errorf("no work area: %dx%d", w, h)
	}
}

func TestPlacement(t *testing.T) {
	const fw, fh = 16, 39
	// 96 DPI, 1920x1040 work area: the full size, centred.
	r := placement(96, fw, fh, rect{Right: 1920, Bottom: 1040})
	w, h := int32(460+fw), int32(760+fh)
	want := rect{Left: (1920 - w) / 2, Top: (1040 - h) / 2}
	want.Right, want.Bottom = want.Left+w, want.Top+h
	if r != want {
		t.Errorf("96 DPI: %+v, want %+v", r, want)
	}

	// 144 DPI on 1920x1032: too tall, so as tall as the work area, at its top.
	r = placement(144, fw, fh, rect{Right: 1920, Bottom: 1032})
	w = 690 + fw
	if r.Top != 0 || r.Bottom != 1032 || r.Right-r.Left != w || r.Left != (1920-w)/2 {
		t.Errorf("144 DPI: %+v", r)
	}

	// A second monitor to the right, its work area below a top taskbar.
	r = placement(96, fw, fh, rect{Left: 1920, Top: 40, Right: 3840, Bottom: 1080})
	w, h = 460+fw, 760+fh
	if r.Left != 1920+(1920-w)/2 || r.Top != 40+(1040-h)/2 || r.Right-r.Left != w || r.Bottom-r.Top != h {
		t.Errorf("second monitor: %+v", r)
	}

	// No work area known: the full size at the origin.
	if r = placement(96, fw, fh, rect{}); r != (rect{Right: 460 + fw, Bottom: 760 + fh}) {
		t.Errorf("no work area: %+v", r)
	}
}
