package collect

import (
	"strings"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Domain-join facts (model.DirectoryJoin). The parsers are OS-independent so
// their tests run everywhere; the per-OS files only gather the raw input.
// Join facts are informational: a failure never fails the check-in.

// fqdnFor builds the computer's DNS name from a host name and an AD domain.
func fqdnFor(host, domain string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), "$")
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" {
		return ""
	}
	if domain == "" || strings.HasSuffix(host, "."+domain) {
		return host
	}
	if i := strings.IndexByte(host, '.'); i >= 0 {
		host = host[:i]
	}
	return host + "." + domain
}

// ParseDsconfigad parses `dsconfigad -show` (macOS Active Directory binding).
// nil when the Mac is not bound.
func ParseDsconfigad(out string) *model.DirectoryJoin {
	vals := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		vals[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	domain := vals["active directory domain"]
	if domain == "" {
		return nil
	}
	j := &model.DirectoryJoin{ADDomain: domain, ADForest: vals["active directory forest"], Source: "dsconfigad"}
	if acct := vals["computer account"]; acct != "" {
		j.DNSHostname = fqdnFor(acct, domain)
	}
	return j
}

// ParseRealmList parses `realm list` (realmd on Linux): the realm this host is
// configured as a member of, preferring Active Directory. nil when not joined.
func ParseRealmList(out, hostname string) *model.DirectoryJoin {
	type realm struct{ name, domain, configured, software string }
	var realms []realm
	for _, l := range strings.Split(out, "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			realms = append(realms, realm{name: strings.TrimSpace(l)})
			continue
		}
		if len(realms) == 0 {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		r := &realms[len(realms)-1]
		switch strings.TrimSpace(k) {
		case "domain-name":
			r.domain = strings.TrimSpace(v)
		case "configured":
			r.configured = strings.TrimSpace(v)
		case "server-software":
			r.software = strings.TrimSpace(v)
		}
	}
	var pick *realm
	for i := range realms {
		r := &realms[i]
		if r.configured == "" || r.configured == "no" {
			continue
		}
		if pick == nil || (r.software == "active-directory" && pick.software != "active-directory") {
			pick = r
		}
	}
	if pick == nil {
		return nil
	}
	domain := pick.domain
	if domain == "" {
		domain = pick.name
	}
	return &model.DirectoryJoin{ADDomain: domain, DNSHostname: fqdnFor(hostname, domain), Source: "realm"}
}
