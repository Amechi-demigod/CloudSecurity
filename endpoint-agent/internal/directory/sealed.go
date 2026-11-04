package directory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// Kerberos signing & sealing transport ("sealed"): LDAP on TCP 389 bound with
// LDAP_AUTH_NEGOTIATE (Kerberos) as the process's identity - the computer
// account under LocalSystem, or the gMSA the service runs as - with
// LDAP_OPT_SIGN and LDAP_OPT_ENCRYPT on, so the SASL security layer gives
// integrity and confidentiality. No DC certificate is needed (unlike LDAPS /
// StartTLS) and it satisfies DCs that require LDAP signing
// (LDAPServerIntegrity=2). Channel binding (LdapEnforceChannelBinding) only
// applies to LDAP over TLS, so it does not concern this transport.
//
// go-ldap cannot do this (it negotiates no SASL security layer), so the
// Windows LDAP library (wldap32.dll) does the work through syscalls (no cgo):
// sealed_windows.go implements ldapAPI. This file holds the logic - options,
// fail-closed sealing check, paging, error mapping - and is tested on every OS
// with a fake ldapAPI. Sealing is required, never optional: if the library
// does not report signing and sealing in effect after the bind, nothing is
// searched and the connection is closed.

// wldap32 option ids and values (winldap.h).
const (
	optProtocolVersion = 0x11
	optReferrals       = 0x08
	optTimeLimit       = 0x04
	optArecExclusive   = 0x98
	optSign            = 0x95
	optEncrypt         = 0x96
	optOn              = 1
	optOff             = 0
)

// LDAP result codes the error mapping explains.
const (
	ldapSuccess             = 0x00
	ldapTimeLimitExceeded   = 0x03
	ldapSizeLimitExceeded   = 0x04
	ldapAuthMethodNotSupp   = 0x07
	ldapStrongAuthRequired  = 0x08
	ldapInvalidCredentials  = 0x31
	ldapInsufficientRights  = 0x32
	ldapUnavailable         = 0x34
	ldapServerDown          = 0x51
	ldapLocalError          = 0x52
	ldapTimeout             = 0x55
	ldapConnectError        = 0x5b
	ldapNoResultsReturned   = 0x5e
	ldapParamError          = 0x59
	ldapNoSuchObject        = 0x20
	ldapUnwillingToPerform  = 0x35
	ldapEncodingDecodingErr = 0x53
)

// ErrNotSealed is returned when the session is not signed and sealed after the bind.
var ErrNotSealed = errors.New("the LDAP session is not signed and sealed after the Kerberos bind; refusing to search " +
	"(unsigned / unsealed LDAP is never used)")

// LDAPError is a wldap32 result code.
type LDAPError struct {
	Op   string
	Code uint32
}

func (e *LDAPError) Error() string {
	return fmt.Sprintf("%s: %s (LDAP 0x%02x)", e.Op, ldapMessage(e.Code), e.Code)
}

// IsUnreachable reports a DC that refused or did not answer the connection.
func (e *LDAPError) IsUnreachable() bool {
	return e.Code == ldapServerDown || e.Code == ldapConnectError || e.Code == ldapTimeout || e.Code == ldapUnavailable
}

func ldapMessage(code uint32) string {
	switch code {
	case ldapServerDown, ldapConnectError:
		return "the domain controller is not reachable on this port"
	case ldapTimeout, ldapTimeLimitExceeded:
		return "timed out"
	case ldapInvalidCredentials:
		return "the Kerberos bind was rejected (invalid credentials: check the collector's identity, its clock and SPN ldap/<dc>)"
	case ldapLocalError:
		return "local Kerberos / SSPI error (no ticket for ldap/<dc>? domain-joined? correct time? DC addressed by DNS name?)"
	case ldapAuthMethodNotSupp:
		return "the domain controller does not support the Negotiate (Kerberos) bind"
	case ldapStrongAuthRequired:
		return "the domain controller requires stronger authentication (signing / sealing could not be negotiated)"
	case ldapInsufficientRights:
		return "insufficient access rights (grant the collector's identity read access on the synced OUs)"
	case ldapNoSuchObject:
		return "the base DN does not exist"
	case ldapUnwillingToPerform:
		return "the domain controller is unwilling to perform the operation"
	case ldapSizeLimitExceeded:
		return "size limit exceeded"
	case ldapParamError:
		return "invalid parameter"
	case ldapEncodingDecodingErr:
		return "encoding / decoding error"
	}
	return "LDAP error"
}

// ldapAPI is the part of wldap32 the sealed transport uses (a fake in tests).
type ldapAPI interface {
	Init(host string, port int) (uintptr, error)
	SetOption(h uintptr, opt int, val uint32) error
	GetOption(h uintptr, opt int) (uint32, error)
	Connect(h uintptr, timeout time.Duration) error
	// BindNegotiate binds with LDAP_AUTH_NEGOTIATE as the current process identity.
	BindNegotiate(h uintptr) error
	// SearchInit starts a paged subtree search (ldap_search_init_page).
	SearchInit(h uintptr, baseDN, filter string, attrs []string, timeLimit time.Duration) (uintptr, error)
	// NextPage returns the next page (ldap_get_next_page_s); done when no more results.
	NextPage(h, search uintptr, timeout time.Duration, pageSize int) (entries []Entry, done bool, err error)
	SearchAbandon(h, search uintptr)
	Unbind(h uintptr)
}

// sealedAPI is the platform implementation (nil where unsupported).
var sealedAPI ldapAPI

// SealedState reports what a sealed connection negotiated (for diagnostics).
type SealedState struct {
	Signed bool
	Sealed bool
}

// connectSealed opens, configures, binds and verifies a signed + sealed session.
func connectSealed(ctx context.Context, api ldapAPI, p *Params, host string) (*sealedSearcher, error) {
	if api == nil {
		return nil, errors.New("Kerberos signing and sealing is only available on the Windows directory collector")
	}
	if p.Auth != AuthKerberos {
		return nil, errors.New("sealed LDAP only binds with Kerberos (computer account or gMSA); passwords need TLS")
	}
	if net.ParseIP(host) != nil {
		return nil, errors.New("Kerberos needs the domain controller's DNS name (ldap/<fqdn> SPN), not an IP address")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := api.Init(host, p.Port)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			api.Unbind(h)
		}
	}()
	for _, o := range []struct {
		opt int
		val uint32
	}{
		{optProtocolVersion, 3},
		{optReferrals, optOff},    // never chase referrals to other servers
		{optArecExclusive, optOn}, // use exactly this host name (the Kerberos SPN)
		{optTimeLimit, uint32(RequestTimeout / time.Second)},
		{optSign, optOn},
		{optEncrypt, optOn},
	} {
		if err := api.SetOption(h, o.opt, o.val); err != nil {
			return nil, fmt.Errorf("setting LDAP option 0x%x: %w", o.opt, err)
		}
	}
	if err := api.Connect(h, DialTimeout); err != nil {
		return nil, err
	}
	if err := api.BindNegotiate(h); err != nil {
		return nil, err
	}
	st, err := sealedState(api, h)
	if err != nil {
		return nil, err
	}
	if !st.Signed || !st.Sealed {
		return nil, ErrNotSealed
	}
	ok = true
	return &sealedSearcher{api: api, h: h, server: host, state: st}, nil
}

func sealedState(api ldapAPI, h uintptr) (SealedState, error) {
	sign, err := api.GetOption(h, optSign)
	if err != nil {
		return SealedState{}, fmt.Errorf("reading LDAP_OPT_SIGN: %w", err)
	}
	enc, err := api.GetOption(h, optEncrypt)
	if err != nil {
		return SealedState{}, fmt.Errorf("reading LDAP_OPT_ENCRYPT: %w", err)
	}
	return SealedState{Signed: sign == optOn, Sealed: enc == optOn}, nil
}

type sealedSearcher struct {
	api    ldapAPI
	h      uintptr
	server string
	state  SealedState
	closed bool
}

func (s *sealedSearcher) Server() string { return s.server }

// Sealed reports the negotiated protection (always signed + sealed once connected).
func (s *sealedSearcher) Sealed() SealedState { return s.state }

func (s *sealedSearcher) Close() error {
	if !s.closed {
		s.closed = true
		s.api.Unbind(s.h)
	}
	return nil
}

// Search pages through the results (the library sends the RFC 2696 paged-results
// control), one page in memory at a time.
func (s *sealedSearcher) Search(ctx context.Context, baseDN, filter string, attrs []string, pageSize int,
	fn func(Entry) error) error {
	search, err := s.api.SearchInit(s.h, baseDN, filter, attrs, RequestTimeout)
	if err != nil {
		return err
	}
	finished := false
	defer func() {
		if !finished {
			s.api.SearchAbandon(s.h, search)
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries, done, err := s.api.NextPage(s.h, search, RequestTimeout, pageSize)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := fn(e); err != nil {
				return err
			}
		}
		if done {
			finished = true
			s.api.SearchAbandon(s.h, search) // frees the search handle
			return nil
		}
	}
}
