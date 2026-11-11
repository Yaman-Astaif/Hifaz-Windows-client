package winres

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"testing"
	"unicode/utf16"
)

func TestObject(t *testing.T) {
	res := []Resource{
		{Type: TypeManifest, ID: 1, Data: []byte("<m/>")},
		{Type: TypeIcon, ID: 2, Data: []byte("two")},
		{Type: TypeIcon, ID: 1, Data: []byte("one")},
	}
	for _, arch := range []string{"amd64", "arm64"} {
		obj, err := Object(arch, res)
		if err != nil {
			t.Fatal(err)
		}
		le := binary.LittleEndian
		if got := le.Uint16(obj[0:]); got != machines[arch].machine {
			t.Fatalf("%s: machine %#x", arch, got)
		}
		if string(obj[20:25]) != ".rsrc" {
			t.Fatalf("%s: section %q", arch, obj[20:28])
		}
		sec := obj[le.Uint32(obj[20+20:]) : le.Uint32(obj[20+20:])+le.Uint32(obj[20+16:])]
		// Root: two types, sorted (icon 3, manifest 24).
		if n := le.Uint16(sec[14:]); n != 2 {
			t.Fatalf("%s: %d types", arch, n)
		}
		if le.Uint32(sec[16:]) != TypeIcon || le.Uint32(sec[24:]) != TypeManifest {
			t.Fatalf("%s: types out of order", arch)
		}
		// Follow icon → first ID → language → data entry → data.
		typeDir := le.Uint32(sec[20:]) &^ 0x80000000
		if id := le.Uint32(sec[typeDir+16:]); id != 1 {
			t.Fatalf("%s: first icon id %d", arch, id)
		}
		nameDir := le.Uint32(sec[typeDir+20:]) &^ 0x80000000
		if lang := le.Uint32(sec[nameDir+16:]); lang != langEnUS {
			t.Fatalf("%s: language %#x", arch, lang)
		}
		de := le.Uint32(sec[nameDir+20:])
		at, size := le.Uint32(sec[de:]), le.Uint32(sec[de+4:])
		if string(sec[at:at+size]) != "one" {
			t.Fatalf("%s: data %q", arch, sec[at:at+size])
		}
		if n := le.Uint16(obj[20+32:]); n != 3 {
			t.Fatalf("%s: %d relocations, want one per resource", arch, n)
		}
	}
	if _, err := Object("mips", res); err == nil {
		t.Fatal("unknown architecture accepted")
	}
	if _, err := Object("amd64", append(res, res[0])); err == nil {
		t.Fatal("duplicate resource accepted")
	}
}

func TestVersionInfo(t *testing.T) {
	data, err := VersionInfo{Version: "0.1.2", ProductName: "Hifaz", FileName: "hifaz.exe"}.Data()
	if err != nil {
		t.Fatal(err)
	}
	le := binary.LittleEndian
	if int(le.Uint16(data)) != len(data) {
		t.Fatalf("length %d, data %d", le.Uint16(data), len(data))
	}
	i := bytes.Index(data, []byte{0xBD, 0x04, 0xEF, 0xFE})
	if i < 0 || i%4 != 0 {
		t.Fatalf("fixed info at %d", i)
	}
	if ms, ls := le.Uint32(data[i+8:]), le.Uint32(data[i+12:]); ms != 0x00000001 || ls != 0x00020000 {
		t.Fatalf("file version %#x %#x", ms, ls)
	}
	for _, s := range []string{"ProductName", "Hifaz", "0.1.2", "hifaz.exe", "040904B0"} {
		if !bytes.Contains(data, wstr(s)[:2*len(utf16.Encode([]rune(s)))]) {
			t.Errorf("%q missing", s)
		}
	}
	for _, bad := range []string{"1.2", "1.2.x", "1.2.70000"} {
		if _, err := (VersionInfo{Version: bad}).Data(); err == nil {
			t.Errorf("version %q accepted", bad)
		}
	}
}

func TestManifestIsXML(t *testing.T) {
	var v struct{}
	if err := xml.Unmarshal(Manifest("Hifaz.hifaz", "0.1.2"), &v); err != nil {
		t.Fatal(err)
	}
}
