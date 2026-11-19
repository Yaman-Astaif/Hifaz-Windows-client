package ipc

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Request{Op: OpConnect, Server: "https://vpn.example.com", PrivateKey: []byte{1, 2, 3}, Since: 7}
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out Request
	if err := Read(&buf, &out); err != nil {
		t.Fatal(err)
	}
	if out.Op != in.Op || out.Server != in.Server || !bytes.Equal(out.PrivateKey, in.PrivateKey) || out.Since != 7 {
		t.Fatalf("%+v", out)
	}
	out.Wipe()
	if !bytes.Equal(out.PrivateKey, []byte{0, 0, 0}) {
		t.Fatal("not wiped")
	}
}

func TestLimits(t *testing.T) {
	if err := Write(new(bytes.Buffer), Request{PSK: make([]byte, MaxMessage)}); err == nil {
		t.Fatal("oversized message written")
	}
	for _, n := range []uint32{0, MaxMessage + 1} {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], n)
		var r Request
		if err := Read(bytes.NewReader(hdr[:]), &r); err == nil {
			t.Fatalf("length %d accepted", n)
		}
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 10)
	var r Request
	if err := Read(bytes.NewReader(append(hdr[:], "{}"...)), &r); err == nil {
		t.Fatal("short body accepted")
	}
}

func TestStatusLinkRoundTrip(t *testing.T) {
	for _, in := range []Status{
		{Generation: 1, State: StateConnected, Owner: OwnerYou},
		{Generation: 2, State: StateConnected, Owner: OwnerYou, Link: LinkNoAnswer,
			Blocker: &Blocker{App: BlockerWireGuard, Tunnels: []string{"wg-client-10"}}},
	} {
		var buf bytes.Buffer
		if err := Write(&buf, in); err != nil {
			t.Fatal(err)
		}
		if in.Link == "" && bytes.Contains(buf.Bytes(), []byte(`"link"`)) {
			t.Fatalf("empty link written: %s", buf.Bytes()[4:])
		}
		var out Status
		if err := Read(&buf, &out); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Fatalf("%+v != %+v", out, in)
		}
	}
}
