package directory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeLDAP plays wldap32 for the sealed transport.
type fakeLDAP struct {
	opts          map[int]uint32
	reportSign    uint32 // what GetOption returns after the bind
	reportEncrypt uint32
	bindErr       error
	connectErr    error
	pages         [][]Entry
	page          int
	pageSizes     []int
	unbound       int
	abandoned     int
	calls         []string
}

func newFake() *fakeLDAP {
	return &fakeLDAP{opts: map[int]uint32{}, reportSign: optOn, reportEncrypt: optOn}
}

func (f *fakeLDAP) Init(host string, port int) (uintptr, error) {
	f.calls = append(f.calls, fmt.Sprintf("init %s:%d", host, port))
	return 42, nil
}
func (f *fakeLDAP) SetOption(_ uintptr, opt int, val uint32) error {
	f.opts[opt] = val
	f.calls = append(f.calls, fmt.Sprintf("set 0x%x=%d", opt, val))
	return nil
}
func (f *fakeLDAP) GetOption(_ uintptr, opt int) (uint32, error) {
	switch opt {
	case optSign:
		return f.reportSign, nil
	case optEncrypt:
		return f.reportEncrypt, nil
	}
	return f.opts[opt], nil
}
func (f *fakeLDAP) Connect(uintptr, time.Duration) error {
	f.calls = append(f.calls, "connect")
	return f.connectErr
}
func (f *fakeLDAP) BindNegotiate(uintptr) error {
	f.calls = append(f.calls, "bind")
	if f.opts[optSign] != optOn || f.opts[optEncrypt] != optOn {
		return errors.New("bind before sign/seal were requested")
	}
	return f.bindErr
}
func (f *fakeLDAP) SearchInit(uintptr, string, string, []string, time.Duration) (uintptr, error) {
	return 7, nil
}
func (f *fakeLDAP) NextPage(_, _ uintptr, _ time.Duration, size int) ([]Entry, bool, error) {
	f.pageSizes = append(f.pageSizes, size)
	if f.page >= len(f.pages) {
		return nil, true, nil
	}
	f.page++
	return f.pages[f.page-1], false, nil
}
func (f *fakeLDAP) SearchAbandon(uintptr, uintptr) { f.abandoned++ }
func (f *fakeLDAP) Unbind(uintptr)                 { f.unbound++ }

func sealedParams() *Params {
	return &Params{Domain: "corp.example.com", Security: SecuritySealed, Port: 389, Auth: AuthKerberos}
}

func entry(cn string) Entry {
	return Entry{DN: "CN=" + cn, Attrs: map[string][][]byte{"cn": {[]byte(cn)}}}
}

func TestSealedSetsOptionsBeforeBindAndPages(t *testing.T) {
	f := newFake()
	f.pages = [][]Entry{{entry("PC1"), entry("PC2")}, {entry("PC3")}}
	s, err := connectSealed(context.Background(), f, sealedParams(), "dc01.corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for opt, want := range map[int]uint32{optProtocolVersion: 3, optSign: optOn, optEncrypt: optOn, optReferrals: optOff,
		optArecExclusive: optOn} {
		if f.opts[opt] != want {
			t.Errorf("option 0x%x = %d, want %d", opt, f.opts[opt], want)
		}
	}
	if got := strings.Join(f.calls, ","); !strings.HasPrefix(got, "init dc01.corp.example.com:389,") ||
		!strings.HasSuffix(got, "connect,bind") {
		t.Errorf("call order %s", got)
	}
	if st := s.Sealed(); !st.Signed || !st.Sealed {
		t.Error("not reported sealed")
	}
	var names []string
	if err := s.Search(context.Background(), "DC=corp", ComputerFilter, []string{"cn"}, 500, func(e Entry) error {
		names = append(names, e.str("cn", 64))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "PC1,PC2,PC3" || f.pageSizes[0] != 500 || f.abandoned != 1 {
		t.Errorf("names %v sizes %v abandoned %d", names, f.pageSizes, f.abandoned)
	}
	_ = s.Close()
	_ = s.Close()
	if f.unbound != 1 {
		t.Errorf("unbound %d times", f.unbound)
	}
}

func TestSealedFailsClosedWhenNotSealed(t *testing.T) {
	for _, tc := range []struct{ sign, enc uint32 }{{optOff, optOn}, {optOn, optOff}, {optOff, optOff}} {
		f := newFake()
		f.reportSign, f.reportEncrypt = tc.sign, tc.enc
		f.pages = [][]Entry{{entry("PC1")}}
		s, err := connectSealed(context.Background(), f, sealedParams(), "dc01.corp.example.com")
		if !errors.Is(err, ErrNotSealed) || s != nil {
			t.Fatalf("%+v: err %v", tc, err)
		}
		if f.page != 0 || f.unbound != 1 {
			t.Errorf("searched %d pages / unbound %d after an unsealed bind", f.page, f.unbound)
		}
	}
}

func TestSealedRefusesPasswordsIPsAndMissingLibrary(t *testing.T) {
	p := sealedParams()
	p.Auth = AuthSimple
	if _, err := connectSealed(context.Background(), newFake(), p, "dc01.corp.example.com"); err == nil {
		t.Error("simple bind over sealed LDAP accepted")
	}
	if _, err := connectSealed(context.Background(), newFake(), sealedParams(), "10.0.0.1"); err == nil {
		t.Error("IP address accepted for Kerberos")
	}
	if _, err := connectSealed(context.Background(), nil, sealedParams(), "dc01.corp.example.com"); err == nil {
		t.Error("nil library accepted")
	}
}

func TestSealedErrorMapping(t *testing.T) {
	f := newFake()
	f.connectErr = &LDAPError{Op: "connect", Code: ldapServerDown}
	_, err := connectSealed(context.Background(), f, sealedParams(), "dc9.corp.example.com")
	if !Unreachable(err) || !strings.Contains(err.Error(), "not reachable") || f.unbound != 1 {
		t.Errorf("%v", err)
	}
	f = newFake()
	f.bindErr = &LDAPError{Op: "Kerberos (Negotiate) bind", Code: ldapLocalError}
	_, err = connectSealed(context.Background(), f, sealedParams(), "dc1.corp.example.com")
	if Unreachable(err) || !strings.Contains(err.Error(), "SSPI") {
		t.Errorf("%v", err)
	}
	for _, code := range []uint32{ldapInvalidCredentials, ldapStrongAuthRequired, ldapInsufficientRights, ldapTimeout, 0x99} {
		if (&LDAPError{Op: "x", Code: code}).Error() == "" {
			t.Error("empty message")
		}
	}
	var oe error = &net.OpError{Op: "dial", Err: errors.New("refused")}
	if !Unreachable(oe) {
		t.Error("dial error not unreachable")
	}
}

func TestSealedParamsOnlyForTheCollector(t *testing.T) {
	raw := map[string]any{"domain": "corp.example.com", "security": "sealed", "auth": "kerberos"}
	old := SealedEnabled
	defer func() { SealedEnabled = old }()
	SealedEnabled = false
	if _, err := ParseDiagParams(raw); err == nil {
		t.Error("sealed accepted without the collector")
	}
	SealedEnabled = true
	p, err := ParseDiagParams(raw)
	if !sealedSupported || !kerberosSupported {
		if err == nil {
			t.Error("sealed accepted on a platform without wldap32")
		}
		return
	}
	if err != nil || p.Port != 389 {
		t.Fatalf("%v %+v", err, p)
	}
	raw["auth"], raw["credential"] = "simple", map[string]any{"username": "u", "password": "p"}
	if _, err := ParseDiagParams(raw); err == nil {
		t.Error("password over sealed LDAP accepted")
	}
}
