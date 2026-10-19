package update

import (
	"fmt"
	"strconv"
	"strings"
)

// Semver is a parsed semantic version (https://semver.org). Build metadata
// ("+abc1234") is kept for display but ignored when comparing.
type Semver struct {
	Major, Minor, Patch uint64
	Pre                 []string
	Build               string
}

// ParseSemver parses MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD] (an optional leading "v" is accepted).
func ParseSemver(s string) (Semver, error) {
	var v Semver
	orig := s
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if s == "" || len(s) > 64 {
		return v, fmt.Errorf("invalid version %q", orig)
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		v.Build = s[i+1:]
		s = s[:i]
		if v.Build == "" || !validIdents(v.Build, false) {
			return v, fmt.Errorf("invalid build metadata in version %q", orig)
		}
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre := s[i+1:]
		s = s[:i]
		if pre == "" || !validIdents(pre, true) {
			return v, fmt.Errorf("invalid pre-release in version %q", orig)
		}
		v.Pre = strings.Split(pre, ".")
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, fmt.Errorf("invalid version %q: want MAJOR.MINOR.PATCH", orig)
	}
	nums := make([]uint64, 3)
	for i, p := range parts {
		if p == "" || (len(p) > 1 && p[0] == '0') {
			return v, fmt.Errorf("invalid version %q", orig)
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return v, fmt.Errorf("invalid version %q", orig)
		}
		nums[i] = n
	}
	v.Major, v.Minor, v.Patch = nums[0], nums[1], nums[2]
	return v, nil
}

func validIdents(s string, noLeadingZero bool) bool {
	for _, id := range strings.Split(s, ".") {
		if id == "" {
			return false
		}
		numeric := true
		for _, c := range id {
			switch {
			case c >= '0' && c <= '9':
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '-':
				numeric = false
			default:
				return false
			}
		}
		if noLeadingZero && numeric && len(id) > 1 && id[0] == '0' {
			return false
		}
	}
	return true
}

// Compare returns -1, 0 or 1 (semver precedence; build metadata ignored).
func (a Semver) Compare(b Semver) int {
	for _, d := range [][2]uint64{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a.Pre) == 0 && len(b.Pre) == 0:
		return 0
	case len(a.Pre) == 0:
		return 1 // a release ranks above its pre-releases
	case len(b.Pre) == 0:
		return -1
	}
	for i := 0; i < len(a.Pre) && i < len(b.Pre); i++ {
		x, y := a.Pre[i], b.Pre[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xerr == nil:
			return -1 // numeric identifiers rank below alphanumeric ones
		case yerr == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	switch {
	case len(a.Pre) < len(b.Pre):
		return -1
	case len(a.Pre) > len(b.Pre):
		return 1
	}
	return 0
}

// CompareVersions parses and compares two version strings.
func CompareVersions(a, b string) (int, error) {
	va, err := ParseSemver(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseSemver(b)
	if err != nil {
		return 0, err
	}
	return va.Compare(vb), nil
}
