package netscan

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
)

// network_subnets: subnet suggestions for the console, read from Active
// Directory Sites and Services (subnet objects under the forest's
// Configuration partition, over the collector's sealed Kerberos LDAP) and from
// the DHCP servers authorised in AD (DHCP Server Management API). Read-only;
// nothing here sends a packet to an address the operator did not choose
// except the RPC calls to the DHCP servers AD already lists.

// ADSite is one AD subnet object (contract: ad_sites[]).
type ADSite struct {
	Site        string `json:"site"`
	Subnet      string `json:"subnet"`
	Description string `json:"description"`
}

// DHCPScope is one DHCP scope (contract: dhcp_scopes[]).
type DHCPScope struct {
	Server string `json:"server"`
	Scope  string `json:"scope"`
	Mask   string `json:"mask"`
	Name   string `json:"name"`
	Start  string `json:"start"`
	End    string `json:"end"`
}

// SubnetsResult is the network_subnets result data (contract).
type SubnetsResult struct {
	ADSites    []ADSite    `json:"ad_sites"`
	DHCPScopes []DHCPScope `json:"dhcp_scopes"`
	Errors     []string    `json:"errors"`
}

// DHCPClient lists the scopes of one DHCP server (Windows: dhcpsapi.dll).
type DHCPClient interface {
	Scopes(ctx context.Context, server string) ([]DHCPScope, error)
}

// ErrUnsupported is returned on platforms without the Windows APIs.
var ErrUnsupported = errors.New("network subnet discovery is unsupported on this platform (it needs the Windows collector)")

// SubnetEnv is what Subnets uses; every part is replaceable in tests.
type SubnetEnv struct {
	Domain  string              // the collector's DNS domain
	Params  *directory.Params   // tests; default: sealed Kerberos to Domain's DCs
	Connect directory.Connector // sealed LDAP (directory.Connect)
	DHCP    DHCPClient          // nil: DHCP is skipped with an error entry
}

// DefaultSubnetEnv builds the production environment for domain, or returns
// ErrUnsupported on non-Windows builds.
func DefaultSubnetEnv(domain string) (*SubnetEnv, error) {
	if !subnetsSupported {
		return nil, ErrUnsupported
	}
	if domain == "" {
		return nil, errors.New("this computer is not domain-joined; AD Sites and DHCP suggestions need a domain")
	}
	return &SubnetEnv{Domain: domain, Connect: directory.Connect, DHCP: defaultDHCP()}, nil
}

const (
	maxSubnetObjects = 5000
	maxDHCPServers   = 50
	maxDHCPScopes    = 5000
)

var (
	serverNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	dhcpValueRe  = regexp.MustCompile(`^i([0-9.]+)\$(?:r([^$]*))?`)
)

// Subnets reads AD sites and DHCP scopes. Failures of one part are reported
// in Errors and never stop the other; only an unusable environment fails.
func Subnets(ctx context.Context, env *SubnetEnv) (*SubnetsResult, error) {
	res := &SubnetsResult{ADSites: []ADSite{}, DHCPScopes: []DHCPScope{}, Errors: []string{}}
	p := env.Params
	if p == nil {
		var err error
		if p, err = directory.ParseDiagParams(map[string]any{"domain": env.Domain, "security": "sealed",
			"auth": "kerberos"}); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	s, err := env.Connect(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("connecting to a domain controller: %w", err)
	}
	defer s.Close()

	roots := configRoots(env.Domain)
	sites, cfg, lastErr := readSites(ctx, s, roots)
	if lastErr != nil {
		res.Errors = append(res.Errors, "AD sites: "+lastErr.Error())
	}
	res.ADSites = sites

	var servers []string
	if cfg != "" {
		var err error
		if servers, err = readDHCPServers(ctx, s, cfg); err != nil {
			res.Errors = append(res.Errors, "DHCP servers in AD: "+err.Error())
		}
	} else if lastErr == nil {
		res.Errors = append(res.Errors, "DHCP servers in AD: the Configuration partition was not found")
	}
	if len(servers) > 0 && env.DHCP == nil {
		res.Errors = append(res.Errors, "DHCP: "+ErrUnsupported.Error())
		return res, nil
	}
	for _, srv := range servers {
		if ctx.Err() != nil {
			res.Errors = append(res.Errors, "stopped: "+ctx.Err().Error())
			break
		}
		scopes, err := env.DHCP.Scopes(ctx, srv)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("DHCP %s: %v", srv, err))
			continue
		}
		for _, sc := range scopes {
			if len(res.DHCPScopes) >= maxDHCPScopes {
				break
			}
			res.DHCPScopes = append(res.DHCPScopes, sc)
		}
	}
	sort.SliceStable(res.ADSites, func(i, j int) bool { return res.ADSites[i].Subnet < res.ADSites[j].Subnet })
	return res, nil
}

// configRoots lists candidate Configuration DNs for domain: the Configuration
// partition hangs off the FOREST root, so a child domain tries its parents
// (longest suffix first, never a single-label suffix).
func configRoots(domain string) []string {
	labels := strings.Split(domain, ".")
	var out []string
	for i := 0; i+2 <= len(labels); i++ {
		out = append(out, "CN=Configuration,"+directory.DomainToDN(strings.Join(labels[i:], ".")))
	}
	if len(out) == 0 {
		out = append(out, "CN=Configuration,"+directory.DomainToDN(domain))
	}
	return out
}

func rdnValue(dn string) string {
	first, _, _ := strings.Cut(dn, ",")
	_, v, _ := strings.Cut(first, "=")
	return v
}

func attr(e directory.Entry, name string) string {
	if v := e.Attrs[strings.ToLower(name)]; len(v) > 0 {
		return strings.TrimSpace(strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, string(v[0])))
	}
	return ""
}

func readSites(ctx context.Context, s directory.Searcher, roots []string) ([]ADSite, string, error) {
	var lastErr error
	for _, cfg := range roots {
		var out []ADSite
		base := "CN=Subnets,CN=Sites," + cfg
		err := s.Search(ctx, base, "(objectClass=subnet)", []string{"cn", "siteObject", "description"}, 500,
			func(e directory.Entry) error {
				if len(out) >= maxSubnetObjects {
					return errors.New("more than " + fmt.Sprint(maxSubnetObjects) + " subnet objects; the rest were not read")
				}
				cidr := attr(e, "cn")
				if pf, err := netip.ParsePrefix(cidr); err != nil || !pf.Addr().Is4() {
					return nil // IPv6 subnets and malformed names are not scan targets
				}
				out = append(out, ADSite{Site: rdnValue(attr(e, "siteObject")), Subnet: cidr, Description: attr(e, "description")})
				return nil
			})
		if err == nil || len(out) > 0 {
			return nonNil(out), cfg, err
		}
		lastErr = err
	}
	return []ADSite{}, "", lastErr
}

func nonNil(s []ADSite) []ADSite {
	if s == nil {
		return []ADSite{}
	}
	return s
}

// readDHCPServers lists the DHCP servers authorised in AD (dhcpClass objects
// under CN=NetServices,CN=Services,CN=Configuration).
func readDHCPServers(ctx context.Context, s directory.Searcher, cfg string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSuffix(strings.TrimSpace(v), ".")
		if v == "" || seen[strings.ToLower(v)] || len(out) >= maxDHCPServers || !serverNameRe.MatchString(v) {
			return
		}
		seen[strings.ToLower(v)] = true
		out = append(out, v)
	}
	err := s.Search(ctx, "CN=NetServices,CN=Services,"+cfg, "(objectClass=dhcpClass)", []string{"cn", "dhcpServers"}, 200,
		func(e directory.Entry) error {
			cn := attr(e, "cn")
			if strings.EqualFold(cn, "DhcpRoot") {
				return nil
			}
			var found bool
			for _, raw := range e.Attrs["dhcpservers"] {
				if m := dhcpValueRe.FindStringSubmatch(string(raw)); m != nil {
					if _, err := netip.ParseAddr(m[1]); err == nil {
						add(m[1])
						found = true
					}
				}
			}
			if !found {
				add(cn) // the object is named after the server (host name or IP)
			}
			return nil
		})
	return out, err
}
