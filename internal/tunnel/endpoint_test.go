package tunnel

import (
	"net/netip"
	"testing"
)

func TestSelectEndpoint(t *testing.T) {
	const host = "vpn.example.org"
	const port = 51820
	unusable := []string{
		"0.0.0.0", "127.0.0.1", "224.0.0.1",
		"::", "::1", "ff02::1",
		"::ffff:0.0.0.0", "::ffff:127.0.0.1", "::ffff:224.0.0.1",
	}
	cases := []struct {
		name    string
		answers []string
		want    string
	}{
		{"skip unusable answers", append(append([]string{}, unusable...), "2001:db8::1"), "2001:db8::1"},
		{"prefer IPv4", []string{"2001:db8::1", "192.0.2.1", "192.0.2.2"}, "192.0.2.1"},
		{"unmap usable IPv4", []string{"2001:db8::1", "::ffff:192.0.2.1"}, "192.0.2.1"},
		{"first usable IPv6", []string{"::1", "2001:db8::1", "2001:db8::2"}, "2001:db8::1"},
		{"all unusable", unusable, ""},
		{"empty", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var addrs []netip.Addr
			for _, answer := range tc.answers {
				addrs = append(addrs, netip.MustParseAddr(answer))
			}
			got, err := selectEndpoint(host, port, addrs)
			if tc.want == "" {
				if err == nil || err.Error() != "resolving vpn.example.org: no usable address" || got.IsValid() {
					t.Fatalf("selectEndpoint = %v, %v; want no usable address error", got, err)
				}
				return
			}
			want := netip.AddrPortFrom(netip.MustParseAddr(tc.want), port)
			if err != nil || got != want {
				t.Fatalf("selectEndpoint = %v, %v; want %v", got, err, want)
			}
		})
	}
}
