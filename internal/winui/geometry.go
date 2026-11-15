package winui

// The window's size and place, worked out without Windows so it is tested
// everywhere. Sizes are client-area pixels at 96 DPI; the frame (title bar
// and borders, from AdjustWindowRectExForDpi) is added by the caller's
// figures frameW and frameH.
const (
	baseWidth  = 460 // the page's fixed size; the user cannot resize it
	baseHeight = 680
)

// System commands (WM_SYSCOMMAND) the fixed window refuses.
const (
	scSize     = 0xF000
	scMaximize = 0xF030
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

func (r rect) empty() bool { return r.Right <= r.Left || r.Bottom <= r.Top }

// scale turns 96-DPI pixels into pixels at dpi.
func scale(v, dpi int) int32 { return int32(v * dpi / 96) }

// placement is where the window opens: the base page size plus the frame,
// no larger than the work area and centred in it. An empty work area
// (unknown) puts the full-size window at the origin.
func placement(dpi int, frameW, frameH int32, work rect) rect {
	w, h := scale(baseWidth, dpi)+frameW, scale(baseHeight, dpi)+frameH
	if work.empty() {
		return rect{Right: w, Bottom: h}
	}
	w, h = min(w, work.Right-work.Left), min(h, work.Bottom-work.Top)
	x := work.Left + (work.Right-work.Left-w)/2
	y := work.Top + (work.Bottom-work.Top-h)/2
	return rect{Left: x, Top: y, Right: x + w, Bottom: y + h}
}

// allowSysCommand reports whether the window passes a WM_SYSCOMMAND on to
// Windows. Sizing and maximizing are refused, whatever started them (the
// window menu, Win+Up, a keyboard shortcut); the low four bits are Windows'
// own and are ignored.
func allowSysCommand(cmd uintptr) bool {
	c := cmd & 0xFFF0
	return c != scSize && c != scMaximize
}
