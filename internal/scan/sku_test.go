package scan

import "testing"

func TestParseInstallationType(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want WindowsSKU
	}{
		{"client", "    InstallationType    REG_SZ    Client", SKUClient},
		{"server", "    InstallationType    REG_SZ    Server", SKUServer},
		{"server core", "    InstallationType    REG_SZ    Server Core", SKUServer},
		{"empty", "", SKUUnknown},
		{"unrecognized", "    InstallationType    REG_SZ    Embedded", SKUUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseInstallationType(c.in); got != c.want {
				t.Errorf("parseInstallationType(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}
