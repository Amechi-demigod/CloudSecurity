package netscan

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	for _, tc := range []struct {
		name     string
		targets  []string
		exclude  []string
		count    int
		contains []string
		absent   []string
	}{
		{"cidr skips network and broadcast", []string{"10.0.0.0/24"}, nil, 254, []string{"10.0.0.1", "10.0.0.254"}, []string{"10.0.0.0", "10.0.0.255"}},
		{"/31 and /32 keep every address", []string{"10.0.0.0/31", "10.0.1.7/32"}, nil, 3, []string{"10.0.0.0", "10.0.0.1", "10.0.1.7"}, nil},
		{"dash range", []string{"192.168.1.10-192.168.1.20"}, nil, 11, []string{"192.168.1.10", "192.168.1.20"}, []string{"192.168.1.21"}},
		{"single address", []string{"172.16.0.5"}, nil, 1, []string{"172.16.0.5"}, nil},
		{"exclusion splits a range", []string{"10.0.0.1-10.0.0.100"}, []string{"10.0.0.10-10.0.0.20", "10.0.0.50"}, 100 - 11 - 1,
			[]string{"10.0.0.9", "10.0.0.21", "10.0.0.51"}, []string{"10.0.0.10", "10.0.0.15", "10.0.0.20", "10.0.0.50"}},
		{"overlapping targets are counted once", []string{"10.0.0.1-10.0.0.50", "10.0.0.40-10.0.0.60"}, nil, 60, nil, nil},
		{"exclusion CIDR", []string{"10.1.0.0/24"}, []string{"10.1.0.128/25"}, 127, []string{"10.1.0.127"}, []string{"10.1.0.128", "10.1.0.200"}},
		{"a /16 is allowed", []string{"10.2.0.0/16"}, nil, 65534, nil, nil},
		{"whole-range exclusion plus other", []string{"10.0.0.0/24", "10.0.1.0/24"}, []string{"10.0.0.0/24"}, 254, []string{"10.0.1.5"}, []string{"10.0.0.5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := ParseTargets(tc.targets, tc.exclude)
			if err != nil {
				t.Fatal(err)
			}
			if s.Count() != tc.count {
				t.Errorf("count %d, want %d", s.Count(), tc.count)
			}
			for _, a := range tc.contains {
				if !s.Contains(netip.MustParseAddr(a)) {
					t.Errorf("%s missing", a)
				}
			}
			for _, a := range tc.absent {
				if s.Contains(netip.MustParseAddr(a)) {
					t.Errorf("%s present", a)
				}
			}
			n := 0
			var prev netip.Addr
			s.Each(func(a netip.Addr) bool {
				if n > 0 && !prev.Less(a) {
					t.Fatalf("not ascending: %s after %s", a, prev)
				}
				prev = a
				n++
				return true
			})
			if n != tc.count {
				t.Errorf("Each visited %d", n)
			}
		})
	}
}

func TestParseTargetsRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		targets []string
		exclude []string
		want    string
	}{
		{"empty", nil, nil, "at least one"},
		{"ipv6", []string{"2001:db8::/64"}, nil, "IPv4"},
		{"ipv6 single", []string{"::1"}, nil, "IPv4"},
		{"hostname", []string{"example.test"}, nil, "IPv4"},
		{"bigger than /16", []string{"10.0.0.0/15"}, nil, "/16"},
		{"/8", []string{"10.0.0.0/8"}, nil, "/16"},
		{"range bigger than /16", []string{"10.0.0.0-10.2.0.0"}, nil, "/16"},
		{"loopback", []string{"127.0.0.0/24"}, nil, "never scanned"},
		{"loopback address", []string{"127.0.0.1"}, nil, "never scanned"},
		{"this network", []string{"0.1.2.3"}, nil, "never scanned"},
		{"link local", []string{"169.254.1.0/24"}, nil, "never scanned"},
		{"multicast", []string{"224.0.0.1"}, nil, "never scanned"},
		{"reserved class E", []string{"240.0.0.0/24"}, nil, "never scanned"},
		{"broadcast", []string{"255.255.255.255"}, nil, "never scanned"},
		{"range touching a forbidden block", []string{"126.255.255.250-127.0.0.2"}, nil, "never scanned"},
		{"reversed range", []string{"10.0.0.9-10.0.0.1"}, nil, "before it starts"},
		{"garbage", []string{"10.0.0.0/33"}, nil, "CIDR"},
		{"bad exclusion", []string{"10.0.0.0/24"}, []string{"nope"}, "exclude"},
		{"all excluded", []string{"10.0.0.0/30"}, []string{"10.0.0.0/24"}, "excluded"},
		{"empty entry", []string{""}, nil, "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseTargets(tc.targets, tc.exclude)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestParseTargetsTotalCap(t *testing.T) {
	// four /16s = 262,136 usable addresses (each /16 loses network + broadcast): allowed
	four := []string{"10.0.0.0/16", "10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"}
	s, err := ParseTargets(four, nil)
	if err != nil || s.Count() != 4*65534 {
		t.Fatalf("%v %v", s, err)
	}
	// ranges (all addresses) go over 262,144
	_, err = ParseTargets([]string{"10.0.0.0-10.0.255.255", "10.1.0.0-10.1.255.255", "10.2.0.0-10.2.255.255",
		"10.3.0.0-10.3.255.255", "10.4.0.0-10.4.0.0"}, nil)
	if err == nil || !strings.Contains(err.Error(), "262144") {
		t.Errorf("err = %v", err)
	}
	// ... unless exclusions bring the scan under the cap
	if _, err = ParseTargets([]string{"10.0.0.0-10.0.255.255", "10.1.0.0-10.1.255.255", "10.2.0.0-10.2.255.255",
		"10.3.0.0-10.3.255.255", "10.4.0.0-10.4.0.0"}, []string{"10.4.0.0"}); err != nil {
		t.Errorf("exact cap rejected: %v", err)
	}
	many := make([]string, 1001)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	if _, err = ParseTargets(many, nil); err == nil {
		t.Error("1001 targets accepted")
	}
}
