package winui

// The window's size and place, worked out without Windows so it is tested
// everywhere. Sizes are client-area pixels at 96 DPI; the frame (title bar
// and borders, from AdjustWindowRectExForDpi) is added by the caller's
// figures frameW and frameH.
const (
	baseWidth  = 460 // the page's size when the window opens
	baseHeight = 760
	minWidth   = 400 // the smallest the user can make it
	minHeight  = 560
)

type point struct{ X, Y int32 }

type rect struct{ Left, Top, Right, Bottom int32 }

func (r rect) empty() bool { return r.Right <= r.Left || r.Bottom <= r.Top }

// scale turns 96-DPI pixels into pixels at dpi.
func scale(v, dpi int) int32 { return int32(v * dpi / 96) }

// minTrackSize is the smallest window (frame included) the user can resize
// to: the minimum page size plus the frame, but never more than the work
// area, so the window always fits on the monitor. An empty work area
// (unknown) caps nothing.
func minTrackSize(dpi int, frameW, frameH int32, work rect) (w, h int32) {
	w, h = scale(minWidth, dpi)+frameW, scale(minHeight, dpi)+frameH
	if !work.empty() {
		w, h = min(w, work.Right-work.Left), min(h, work.Bottom-work.Top)
	}
	return w, h
}

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
