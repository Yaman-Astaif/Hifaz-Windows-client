package version

import "testing"

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.1.0", 0},
		{"v0.1.0", "0.1.0", 0},
		{"0.1.0", "0.2.0", -1},
		{"0.10.0", "0.9.9", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.1.0-dev", "0.1.0", -1},
		{"0.1.0", "0.1.0-rc1", 1},
		{"0.1.0-rc1", "0.1.0-rc2", -1},
	} {
		got, err := Compare(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "1", "1.2", "1.2.3.4", "1.x.3", "01.2.3", "-1.2.3"} {
		if _, err := Compare(bad, "0.1.0"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
