package directory

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type fakeConn struct{ net.Conn }

func (fakeConn) Close() error { return nil }

type fakeSearcher struct {
	server  string
	entries []Entry
	sealed  bool
}

func (s *fakeSearcher) Search(_ context.Context, _, _ string, _ []string, _ int, fn func(Entry) error) error {
	for _, e := range s.entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}
func (s *fakeSearcher) Server() string { return s.server }
func (s *fakeSearcher) Close() error   { return nil }

type sealedFake struct{ fakeSearcher }

func (s *sealedFake) Sealed() SealedState { return SealedState{Signed: true, Sealed: true} }

func diag(dns []string, fromDNS bool, down map[string]bool, connect func(string) (Searcher, error)) *Diagnostics {
	return &Diagnostics{
		Locate: func(context.Context, *Params) ([]string, bool) { return dns, fromDNS },
		Dial: func(_ context.Context, addr string, _ time.Duration) (net.Conn, error) {
			h, _, _ := net.SplitHostPort(addr)
			if down[h] {
				return nil, &net.OpError{Op: "dial", Err: errors.New("i/o timeout")}
			}
			return fakeConn{}, nil
		},
		TLSCheck: func(context.Context, *Params, string) error { return nil },
		Connect:  func(_ context.Context, _ *Params, h string) (Searcher, error) { return connect(h) },
		Identity: `CORP\COLL01$`,
	}
}

func statuses(r DiagResult) string {
	var s []string
	for _, st := range r.Steps {
		s = append(s, st.ID+"="+st.Status)
	}
	return strings.Join(s, " ")
}

func TestDiagnosticsSealedWithStaleSRV(t *testing.T) {
	many := []Entry{entry("A"), entry("B"), entry("C"), entry("D"), entry("E"), entry("F")}
	d := diag([]string{"old-dc.corp.example.com", "dc01.corp.example.com"}, true,
		map[string]bool{"old-dc.corp.example.com": true}, func(h string) (Searcher, error) {
			return &sealedFake{fakeSearcher{server: h, entries: many}}, nil
		})
	r := d.Run(context.Background(), sealedParams())
	if got := statuses(r); got != "dc_locator=pass port=warn certificate=skip bind=pass read=pass" {
		t.Fatal(got)
	}
	if !strings.Contains(r.Steps[1].Detail, "old-dc.corp.example.com: listed in DNS as a DC but not responding") {
		t.Error(r.Steps[1].Detail)
	}
	if !r.SignedSealed || r.Server != "dc01.corp.example.com" || !strings.Contains(r.Steps[3].Detail, "signed+sealed: yes") ||
		!strings.Contains(r.Steps[3].Detail, `CORP\COLL01$`) || !strings.Contains(r.Steps[4].Detail, "5 object(s)") || !r.OK() {
		t.Errorf("%+v", r)
	}
}

func TestDiagnosticsFailuresSkipTheRest(t *testing.T) {
	d := diag([]string{"dc01.corp.example.com"}, true, map[string]bool{"dc01.corp.example.com": true}, nil)
	r := d.Run(context.Background(), sealedParams())
	if got := statuses(r); got != "dc_locator=pass port=fail certificate=skip bind=skip read=skip" || r.OK() {
		t.Fatal(got)
	}
	// LDAPS with a bad certificate.
	d = diag([]string{"dc01.corp.example.com"}, true, nil, nil)
	d.TLSCheck = func(context.Context, *Params, string) error {
		return errors.New("x509: certificate signed by unknown authority")
	}
	p := &Params{Domain: "corp.example.com", Security: SecurityLDAPS, Port: 636, Auth: AuthSimple, Username: "svc",
		Password: "Sup3r-secret"}
	r = d.Run(context.Background(), p)
	if got := statuses(r); got != "dc_locator=pass port=pass certificate=fail bind=skip read=skip" {
		t.Fatal(got)
	}
	// Bind rejected: the password never appears.
	d = diag([]string{"dc01.corp.example.com"}, true, nil, func(string) (Searcher, error) {
		return nil, errors.New("invalid credentials for svc / Sup3r-secret")
	})
	r = d.Run(context.Background(), p)
	if got := statuses(r); got != "dc_locator=pass port=pass certificate=pass bind=fail read=skip" ||
		strings.Contains(r.Steps[3].Detail, "Sup3r-secret") {
		t.Fatal(got, r.Steps[3].Detail)
	}
	// No SRV records: warn and try the domain name.
	d = diag([]string{"corp.example.com"}, false, nil, func(h string) (Searcher, error) {
		return &fakeSearcher{server: h}, nil
	})
	r = d.Run(context.Background(), &Params{Domain: "corp.example.com", Security: SecurityLDAPS, Port: 636, Auth: AuthKerberos})
	if got := statuses(r); got != "dc_locator=warn port=pass certificate=pass bind=pass read=warn" {
		t.Fatal(got)
	}
}

func TestParseDiagParams(t *testing.T) {
	if _, err := ParseDiagParams(map[string]any{"domain": "corp.example.com", "auth": "simple", "evil": 1}); err == nil {
		t.Error("unknown parameter accepted")
	}
	p, err := ParseDiagParams(map[string]any{"domain": "corp.example.com", "security": "ldaps", "auth": "simple",
		"credential": map[string]any{"username": "svc", "password": "pw"}, "source_id": ""})
	if err != nil || p.Port != 636 || p.Password != "pw" {
		t.Fatal(err, p)
	}
}
