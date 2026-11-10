// Package netscan is the network-discovery half of the dedicated collector
// (commands network_subnets and network_scan; docs/NETWORK_DISCOVERY_COLLECTOR.md).
//
// It is read-only: it pings, ARP-resolves and TCP-connects to addresses the
// operator chose, and reads SNMP with GET / GETBULK only. It never logs in to
// anything, never guesses passwords (beyond the two default SNMP communities
// "public" and "private", one request each), never sends SNMP SET and never
// runs exploits. Secrets (SNMP communities and v3 passwords) live in memory
// for the duration of one scan and never reach logs, disk, diagnostics or
// results.
package netscan

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Hard limits, re-validated on the collector whatever the server sent.
const (
	MaxRangeAddresses = 1 << 16 // each range at most a /16
	MaxTotalAddresses = 1 << 18 // 262,144 addresses per scan
	maxTargetEntries  = 1000
)

// forbidden are address blocks that are never scanned: "this network",
// loopback, link-local and multicast / reserved (224.0.0.0 and above).
var forbidden = [][2]uint32{
	{0x00000000, 0x00FFFFFF}, // 0.0.0.0/8
	{0x7F000000, 0x7FFFFFFF}, // 127.0.0.0/8
	{0xA9FE0000, 0xA9FEFFFF}, // 169.254.0.0/16
	{0xE0000000, 0xFFFFFFFF}, // 224.0.0.0/4 and 240.0.0.0/4 (incl. broadcast)
}

type span struct{ lo, hi uint32 } // inclusive

// AddrSet is a set of IPv4 addresses kept as sorted, non-overlapping spans.
type AddrSet struct{ spans []span }

func addrU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32Addr(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

// Count is the number of addresses in the set.
func (s *AddrSet) Count() int {
	n := 0
	for _, sp := range s.spans {
		n += int(sp.hi-sp.lo) + 1
	}
	return n
}

// Contains reports whether a is in the set.
func (s *AddrSet) Contains(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	u := addrU32(a)
	i := sort.Search(len(s.spans), func(i int) bool { return s.spans[i].hi >= u })
	return i < len(s.spans) && s.spans[i].lo <= u
}

// Each calls fn for every address in ascending order until fn returns false.
func (s *AddrSet) Each(fn func(netip.Addr) bool) {
	for _, sp := range s.spans {
		for u := uint64(sp.lo); u <= uint64(sp.hi); u++ {
			if !fn(u32Addr(uint32(u))) {
				return
			}
		}
	}
}

func merge(in []span) []span {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo < in[j].lo })
	out := []span{in[0]}
	for _, sp := range in[1:] {
		last := &out[len(out)-1]
		if uint64(sp.lo) <= uint64(last.hi)+1 {
			last.hi = max(last.hi, sp.hi)
		} else {
			out = append(out, sp)
		}
	}
	return out
}

func subtract(in, ex []span) []span {
	var out []span
	for _, sp := range in {
		cur := sp
		keep := true
		for _, e := range ex {
			if e.hi < cur.lo || e.lo > cur.hi {
				continue
			}
			if e.lo > cur.lo {
				out = append(out, span{cur.lo, e.lo - 1})
			}
			if e.hi >= cur.hi {
				keep = false
				break
			}
			cur.lo = e.hi + 1
		}
		if keep {
			out = append(out, cur)
		}
	}
	return out
}

// parseSpan parses "a.b.c.d", "a.b.c.d/n" or "a.b.c.d-e.f.g.h" (IPv4 only).
// For a CIDR of /30 or shorter the network and broadcast addresses are left
// out (they are not hosts).
func parseSpan(s string, hostsOnly bool) (span, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return span{}, errors.New("empty address range")
	}
	switch {
	case strings.Contains(s, "/"):
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return span{}, fmt.Errorf("%q is not an IPv4 CIDR", s)
		}
		p = p.Masked()
		lo := addrU32(p.Addr())
		hi := lo
		if p.Bits() < 32 {
			hi = lo | (^uint32(0) >> uint(p.Bits()))
		}
		if hostsOnly && p.Bits() <= 30 {
			lo++
			hi--
		}
		return span{lo, hi}, nil
	case strings.Contains(s, "-"):
		a, b, _ := strings.Cut(s, "-")
		x, err1 := netip.ParseAddr(strings.TrimSpace(a))
		y, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil || !x.Is4() || !y.Is4() {
			return span{}, fmt.Errorf("%q is not an IPv4 range a.b.c.d-e.f.g.h", s)
		}
		if addrU32(y) < addrU32(x) {
			return span{}, fmt.Errorf("range %q ends before it starts", s)
		}
		return span{addrU32(x), addrU32(y)}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return span{}, fmt.Errorf("%q is not an IPv4 address, CIDR or range", s)
	}
	return span{addrU32(a), addrU32(a)}, nil
}

func parseTargets(targets, exclude []string, allowReserved bool) (*AddrSet, error) {
	if len(targets) == 0 {
		return nil, errors.New("targets must list at least one range")
	}
	if len(targets) > maxTargetEntries || len(exclude) > maxTargetEntries {
		return nil, fmt.Errorf("at most %d targets and %d exclusions", maxTargetEntries, maxTargetEntries)
	}
	var inc, exc []span
	for _, t := range targets {
		sp, err := parseSpan(t, true)
		if err != nil {
			return nil, err
		}
		if uint64(sp.hi-sp.lo)+1 > MaxRangeAddresses {
			return nil, fmt.Errorf("range %q is larger than a /16 (%d addresses)", t, MaxRangeAddresses)
		}
		if !allowReserved {
			for _, f := range forbidden {
				if sp.lo <= f[1] && sp.hi >= f[0] {
					return nil, fmt.Errorf("range %q includes addresses that are never scanned (0/8, 127/8, 169.254/16, 224/4 and above)", t)
				}
			}
		}
		inc = append(inc, sp)
	}
	for _, e := range exclude {
		sp, err := parseSpan(e, false)
		if err != nil {
			return nil, fmt.Errorf("exclude: %w", err)
		}
		exc = append(exc, sp)
	}
	set := &AddrSet{spans: subtract(merge(inc), merge(exc))}
	n := set.Count()
	if n == 0 {
		return nil, errors.New("every target address is excluded")
	}
	if n > MaxTotalAddresses {
		return nil, fmt.Errorf("%d addresses is more than the %d allowed per scan", n, MaxTotalAddresses)
	}
	return set, nil
}

// ParseTargets validates and expands targets minus exclusions.
func ParseTargets(targets, exclude []string) (*AddrSet, error) {
	return parseTargets(targets, exclude, false)
}
