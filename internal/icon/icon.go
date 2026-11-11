// Package icon draws the Hifaz icon: a shield with a check mark, in the
// colours of the Hifaz palette. It is a plain generic sign, not a logo (the
// app's logo slot stays empty). The same drawing is used for the program
// file, the window, the Start menu, the installer and the tray, so they all
// match; the tray shows a grey shield without the mark when not connected.
package icon

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"math"
)

// Style is a variant of the icon.
type Style int

const (
	App          Style = iota // the program's icon
	Connected                 // the tray while connected (same as App)
	Disconnected              // the tray while not connected
)

type rgb struct{ r, g, b float64 }

var (
	teal     = rgb{0x0b, 0x4a, 0x40} // the window's header colour
	tealTop  = rgb{0x15, 0x66, 0x58}
	gold     = rgb{0xc9, 0xa9, 0x6e} // the header's rule
	grey     = rgb{0x7a, 0x7a, 0x7a}
	greyTop  = rgb{0x9a, 0x9a, 0x9a}
	white    = rgb{0xff, 0xff, 0xff}
	samples  = 4 // per axis, for anti-aliasing
	tipY     = 0.95
	topY     = 0.06
	halfW    = 0.40
	shoulder = 0.48 // where the sides start to curve to the tip
)

// shieldHalfWidth is the shield's half width at height y (0 at the top, 1
// at the bottom), or a negative value outside it.
func shieldHalfWidth(y float64) float64 {
	switch {
	case y < topY || y > tipY:
		return -1
	case y <= shoulder:
		// A slightly concave top edge: the corners stand a little higher.
		return halfW
	default:
		t := (y - shoulder) / (tipY - shoulder)
		return halfW * math.Pow(1-t*t, 0.55) * (1 - 0.25*t)
	}
}

// inShield reports whether (x, y) in [0,1]² is inside a shield scaled by s
// around the shield's centre.
func inShield(x, y, s float64) bool {
	cx, cy := 0.5, (topY+tipY)/2
	x, y = cx+(x-cx)/s, cy+(y-cy)/s
	w := shieldHalfWidth(y)
	if w < 0 || math.Abs(x-0.5) > w {
		return false
	}
	// Round the two top corners.
	const r = 0.09
	if y < topY+r && math.Abs(x-0.5) > halfW-r {
		dx := math.Abs(x-0.5) - (halfW - r)
		dy := topY + r - y
		return dx*dx+dy*dy <= r*r
	}
	return true
}

// segDist is the distance from p to the segment ab.
func segDist(px, py, ax, ay, bx, by float64) float64 {
	vx, vy := bx-ax, by-ay
	t := ((px-ax)*vx + (py-ay)*vy) / (vx*vx + vy*vy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*vx), py-(ay+t*vy))
}

func inCheck(x, y, width float64) bool {
	const ax, ay, bx, by, cx, cy = 0.31, 0.50, 0.45, 0.65, 0.70, 0.36
	return segDist(x, y, ax, ay, bx, by) <= width/2 || segDist(x, y, bx, by, cx, cy) <= width/2
}

// Pixels draws the icon as size×size BGRA pixels, top-down, with
// premultiplied alpha (what Windows icons and DIB sections expect).
func Pixels(size int, s Style) []byte {
	fill, top := teal, tealTop
	mark := s != Disconnected
	if !mark {
		fill, top = grey, greyTop
	}
	rim := size >= 32 && mark // too thin to read below 32 pixels
	checkW := 0.12
	if size < 24 {
		checkW = 0.16 // bolder when tiny
	}
	px := make([]byte, size*size*4)
	n := float64(samples * samples)
	for py := 0; py < size; py++ {
		for pxl := 0; pxl < size; pxl++ {
			var r, g, b, a float64
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					x := (float64(pxl) + (float64(sx)+0.5)/float64(samples)) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/float64(samples)) / float64(size)
					if !inShield(x, y, 1) {
						continue
					}
					var c rgb
					switch {
					case mark && inCheck(x, y, checkW):
						c = white
					case rim && !inShield(x, y, 0.9):
						c = gold
					default: // a soft light from the top
						t := math.Min(1, math.Max(0, (y-topY)/(tipY-topY)))
						c = rgb{top.r + (fill.r-top.r)*t, top.g + (fill.g-top.g)*t, top.b + (fill.b-top.b)*t}
					}
					r, g, b, a = r+c.r, g+c.g, b+c.b, a+1
				}
			}
			i := (py*size + pxl) * 4
			// Averaging colour·coverage gives premultiplied values.
			px[i+0] = byte(math.Round(b / n))
			px[i+1] = byte(math.Round(g / n))
			px[i+2] = byte(math.Round(r / n))
			px[i+3] = byte(math.Round(255 * a / n))
		}
	}
	return px
}

// Image returns the icon as an image (straight alpha).
func Image(size int, s Style) *image.NRGBA {
	px := Pixels(size, s)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i := 0; i < size*size; i++ {
		b, g, r, a := px[i*4], px[i*4+1], px[i*4+2], px[i*4+3]
		if a == 0 {
			continue
		}
		un := func(v byte) uint8 { return uint8(math.Min(255, math.Round(float64(v)*255/float64(a)))) }
		img.Pix[i*4+0], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = un(r), un(g), un(b), a
	}
	return img
}

// Sizes are the sizes in the program's icon: what Explorer, the taskbar,
// the Start menu and the title bar ask for, at 100 % to 300 % scaling.
var Sizes = []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256}

// Entry is one image of an icon file, PNG-encoded.
type Entry struct {
	Size int
	PNG  []byte
}

// Entries draws the program's icon at every size in Sizes.
func Entries() ([]Entry, error) {
	var out []Entry
	for _, s := range Sizes {
		var buf bytes.Buffer
		if err := png.Encode(&buf, Image(s, App)); err != nil {
			return nil, err
		}
		out = append(out, Entry{s, buf.Bytes()})
	}
	return out, nil
}

// dirEntry is the part shared by .ico files and icon resources.
func dirEntry(e Entry) []byte {
	b := make([]byte, 12)
	dim := byte(e.Size)
	if e.Size >= 256 {
		dim = 0 // 0 means 256
	}
	b[0], b[1] = dim, dim
	binary.LittleEndian.PutUint16(b[4:], 1)  // planes
	binary.LittleEndian.PutUint16(b[6:], 32) // bits per pixel
	binary.LittleEndian.PutUint32(b[8:], uint32(len(e.PNG)))
	return b
}

func header(n int) []byte {
	b := make([]byte, 6)
	binary.LittleEndian.PutUint16(b[2:], 1) // icon
	binary.LittleEndian.PutUint16(b[4:], uint16(n))
	return b
}

// ICO builds an .ico file from entries.
func ICO(entries []Entry) []byte {
	out := header(len(entries))
	offset := 6 + 16*len(entries)
	for _, e := range entries {
		out = append(out, dirEntry(e)...)
		out = binary.LittleEndian.AppendUint32(out, uint32(offset))
		offset += len(e.PNG)
	}
	for _, e := range entries {
		out = append(out, e.PNG...)
	}
	return out
}

// GroupResource builds an RT_GROUP_ICON resource whose images are the
// RT_ICON resources firstID, firstID+1, …
func GroupResource(entries []Entry, firstID uint16) []byte {
	out := header(len(entries))
	for i, e := range entries {
		out = append(out, dirEntry(e)...)
		out = binary.LittleEndian.AppendUint16(out, firstID+uint16(i))
	}
	return out
}
