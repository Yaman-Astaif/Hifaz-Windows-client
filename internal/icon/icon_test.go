package icon

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestPixels(t *testing.T) {
	for _, size := range []int{16, 32, 256} {
		for _, s := range []Style{App, Connected, Disconnected} {
			px := Pixels(size, s)
			if len(px) != size*size*4 {
				t.Fatalf("%d: %d bytes", size, len(px))
			}
			for i := 0; i < len(px); i += 4 {
				if a := px[i+3]; px[i] > a || px[i+1] > a || px[i+2] > a {
					t.Fatalf("%d/%d: pixel %d is not premultiplied", size, s, i/4)
				}
			}
			if px[3] != 0 { // the corner is outside the shield
				t.Errorf("%d/%d: corner not transparent", size, s)
			}
		}
	}
	// Centre-left of the shield is its fill: teal, or grey when not connected.
	at := func(s Style) (r, g, b byte) {
		img := Image(64, s)
		c := img.NRGBAAt(16, 40)
		return c.R, c.G, c.B
	}
	if r, g, b := at(App); !(g > r && g > b) {
		t.Errorf("app fill %d,%d,%d is not teal", r, g, b)
	}
	if r, g, b := at(Disconnected); r != g || g != b {
		t.Errorf("not-connected fill %d,%d,%d is not grey", r, g, b)
	}
}

func TestICO(t *testing.T) {
	entries, err := Entries()
	if err != nil {
		t.Fatal(err)
	}
	ico := ICO(entries)
	le := binary.LittleEndian
	if le.Uint16(ico[2:]) != 1 || int(le.Uint16(ico[4:])) != len(Sizes) {
		t.Fatalf("header % x", ico[:6])
	}
	for i, e := range entries {
		d := ico[6+16*i:]
		size, off := le.Uint32(d[8:]), le.Uint32(d[12:])
		img, err := png.Decode(bytes.NewReader(ico[off : off+size]))
		if err != nil || img.Bounds().Dx() != e.Size {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	if g := GroupResource(entries, 1); len(g) != 6+14*len(entries) || le.Uint16(g[6+12:]) != 1 {
		t.Fatalf("group resource")
	}
}
