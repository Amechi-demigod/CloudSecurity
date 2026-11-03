package directory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Real backend: github.com/go-ldap/ldap/v3 (MIT). Only Bind and Search are used.

// Timeouts (variables so tests can shorten them).
var (
	DialTimeout    = 15 * time.Second
	RequestTimeout = 2 * time.Minute
	maxLocatedDCs  = 10
)

// lookupSRV is replaceable in tests.
var lookupSRV = net.DefaultResolver.LookupSRV

// systemRoots is replaceable in tests (nil pool = an empty pool plus ca_pem).
var systemRoots = x509.SystemCertPool

// LocateDCs returns the configured servers, or the domain's DCs from DNS
// (_ldap._tcp.dc._msdcs.<domain>, already sorted by priority / weight), or
// the domain name itself as a last resort.
func LocateDCs(ctx context.Context, p *Params) []string {
	if len(p.Servers) > 0 {
		return p.Servers
	}
	_, srvs, err := lookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+p.Domain)
	var out []string
	if err == nil {
		for _, s := range srvs {
			h := strings.TrimSuffix(s.Target, ".")
			if h != "" && len(out) < maxLocatedDCs {
				out = append(out, h)
			}
		}
	}
	if len(out) == 0 {
		out = []string{p.Domain}
	}
	return out
}

// TLSConfig builds the TLS settings for host: system roots plus the optional
// pinned CA, TLS 1.2+, certificate and host name always verified.
func TLSConfig(p *Params, host string) (*tls.Config, error) {
	pool, err := systemRoots()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if p.CAPEM != "" {
		if _, err := CertPool(p.CAPEM); err != nil {
			return nil, err
		}
		pool.AppendCertsFromPEM([]byte(p.CAPEM))
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: pool}, nil
}

// Connect is the real Connector: it tries each DC in order until one accepts
// a TLS connection and the bind.
func Connect(ctx context.Context, p *Params) (Searcher, error) {
	hosts := LocateDCs(ctx, p)
	var errs []string
	for _, h := range hosts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s, err := connectOne(ctx, p, h)
		if err == nil {
			return s, nil
		}
		errs = append(errs, h+": "+Redact(err.Error(), p.Secrets()...))
	}
	return nil, fmt.Errorf("no domain controller accepted the connection (%s)", strings.Join(errs, "; "))
}

func connectOne(ctx context.Context, p *Params, host string) (Searcher, error) {
	tc, err := TLSConfig(p, host)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(p.Port))
	dialer := &net.Dialer{Timeout: DialTimeout}
	var conn *ldap.Conn
	switch p.Security {
	case SecurityLDAPS:
		conn, err = ldap.DialURL("ldaps://"+addr, ldap.DialWithTLSDialer(tc, dialer))
	case SecurityStartTLS:
		conn, err = ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
		if err == nil {
			conn.SetTimeout(RequestTimeout)
			if err = conn.StartTLS(tc); err != nil {
				conn.Close()
				return nil, fmt.Errorf("StartTLS: %w", err)
			}
		}
	default:
		return nil, errors.New("plain LDAP is not supported")
	}
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	conn.SetTimeout(RequestTimeout)
	state, ok := conn.TLSConnectionState()
	if !ok || !state.HandshakeComplete || len(state.PeerCertificates) == 0 {
		conn.Close()
		return nil, errors.New("connection is not protected by TLS; refusing to bind")
	}
	switch p.Auth {
	case AuthSimple:
		err = conn.Bind(p.Username, p.Password)
	case AuthKerberos:
		err = kerberosBind(conn, host, state.PeerCertificates[0])
	default:
		err = errors.New("unsupported auth")
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("bind (%s): %w", p.Auth, err)
	}
	return &ldapSearcher{conn: conn, server: host}, nil
}

type ldapSearcher struct {
	conn   *ldap.Conn
	server string
}

func (s *ldapSearcher) Server() string { return s.server }
func (s *ldapSearcher) Close() error   { return s.conn.Close() }

// Search pages through the results with the RFC 2696 paged-results control,
// keeping one page in memory at a time.
func (s *ldapSearcher) Search(ctx context.Context, baseDN, filter string, attrs []string, pageSize int,
	fn func(Entry) error) error {
	// Cancellation closes the connection, which unblocks a pending request.
	stop := context.AfterFunc(ctx, func() { _ = s.conn.Close() })
	defer stop()
	paging := ldap.NewControlPaging(uint32(pageSize))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req := ldap.NewSearchRequest(baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter,
			attrs, []ldap.Control{paging})
		res, err := s.conn.Search(req)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		for _, e := range res.Entries {
			en := Entry{DN: e.DN, Attrs: make(map[string][][]byte, len(e.Attributes))}
			for _, a := range e.Attributes {
				en.Attrs[strings.ToLower(a.Name)] = a.ByteValues
			}
			if err := fn(en); err != nil {
				return err
			}
		}
		pc, ok := ldap.FindControl(res.Controls, ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(pc.Cookie) == 0 {
			return nil
		}
		paging.SetCookie(pc.Cookie)
	}
}
