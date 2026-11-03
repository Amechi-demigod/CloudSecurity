package directory

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/client"
)

// A tiny in-process LDAP responder: simple bind, StartTLS and paged subtree
// searches, enough to drive the real go-ldap backend end to end (TLS
// verification against a pinned CA, bind, paging, binary attributes).

func testCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type ldapServer struct {
	ln        net.Listener
	tlsCfg    *tls.Config
	startTLS  bool // plain listener that requires StartTLS before bind
	user, pw  string
	computers []Entry
	users     []Entry
	mu        sync.Mutex
	pages     int
	binds     int
	plainBind bool // a bind arrived before TLS (must never happen)
}

func (s *ldapServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func msg(id int64, op *ber.Packet, controls ...*ber.Packet) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	env.AppendChild(op)
	if len(controls) > 0 {
		cs := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
		for _, c := range controls {
			cs.AppendChild(c)
		}
		env.AppendChild(cs)
	}
	return env.Bytes()
}

func result(tag ber.Tag, code int64) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return op
}

func (s *ldapServer) handle(conn net.Conn) {
	defer conn.Close()
	isTLS := !s.startTLS
	if isTLS {
		conn = tls.Server(conn, s.tlsCfg)
	}
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case ldap.ApplicationExtendedRequest:
			if string(op.Children[0].Data.Bytes()) != "1.3.6.1.4.1.1466.20037" {
				_, _ = conn.Write(msg(id, result(ldap.ApplicationExtendedResponse, 2)))
				continue
			}
			_, _ = conn.Write(msg(id, result(ldap.ApplicationExtendedResponse, 0)))
			tc := tls.Server(conn, s.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			conn, isTLS = tc, true
		case ldap.ApplicationBindRequest:
			name := op.Children[1].Value.(string)
			pw := string(op.Children[2].Data.Bytes())
			s.mu.Lock()
			s.binds++
			if !isTLS {
				s.plainBind = true
			}
			s.mu.Unlock()
			code := int64(49) // invalidCredentials
			if isTLS && name == s.user && pw == s.pw {
				code = 0
			}
			_, _ = conn.Write(msg(id, result(ldap.ApplicationBindResponse, code)))
		case ldap.ApplicationSearchRequest:
			filter, _ := ldap.DecompileFilter(op.Children[6])
			src := s.users
			if strings.Contains(filter, "objectCategory=computer") {
				src = s.computers
			}
			size, start := 1000, 0
			if len(p.Children) > 2 {
				for _, cp := range p.Children[2].Children {
					c, err := ldap.DecodeControl(cp)
					if pc, ok := c.(*ldap.ControlPaging); err == nil && ok {
						size = int(pc.PagingSize)
						if len(pc.Cookie) > 0 {
							start, _ = strconv.Atoi(string(pc.Cookie))
						}
					}
				}
			}
			end := min(start+size, len(src))
			for _, e := range src[start:end] {
				ent := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
				ent.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, ""))
				attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				for name, vals := range e.Attrs {
					a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
					set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
					for _, v := range vals {
						set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), ""))
					}
					a.AppendChild(set)
					attrs.AppendChild(a)
				}
				ent.AppendChild(attrs)
				_, _ = conn.Write(msg(id, ent))
			}
			cookie := ""
			if end < len(src) {
				cookie = strconv.Itoa(end)
			}
			pc := ldap.NewControlPaging(0)
			pc.SetCookie([]byte(cookie))
			s.mu.Lock()
			s.pages++
			s.mu.Unlock()
			_, _ = conn.Write(msg(id, result(ldap.ApplicationSearchResultDone, 0), pc.Encode()))
		default: // unbind / abandon
			return
		}
	}
}

func startLDAP(t *testing.T, startTLS bool) (*ldapServer, string) {
	t.Helper()
	cert, caPEM := testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &ldapServer{ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		startTLS: startTLS, user: "svc-ldap@corp.example.com", pw: testPass}
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s, caPEM
}

// batchServer is the server's ingest endpoint.
type batchServer struct {
	mu      sync.Mutex
	batches []Batch
	errs    []string
}

func (b *batchServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	fail := func(s string) { b.errs = append(b.errs, s); w.WriteHeader(400) }
	if r.Method != http.MethodPost || r.URL.Path != UploadPrefix+testRun+"/batches" {
		fail("path " + r.URL.Path)
		return
	}
	if r.Header.Get("Authorization") != "Bearer cnd_secret" || r.Header.Get("X-Directory-Sync-Token") != testToken ||
		r.Header.Get("Content-Encoding") != "gzip" || r.Header.Get("Content-Type") != "application/json" {
		fail("headers")
		return
	}
	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		fail("gzip")
		return
	}
	raw, _ := io.ReadAll(zr)
	var bt Batch
	if err := json.Unmarshal(raw, &bt); err != nil {
		fail("json")
		return
	}
	if bt.Seq != len(b.batches) {
		w.WriteHeader(409)
		return
	}
	if bytes.Contains(raw, []byte(testPass)) {
		fail("password in a batch")
		return
	}
	b.batches = append(b.batches, bt)
	_, _ = io.WriteString(w, `{"accepted":1,"duplicate":false}`)
}

func e2eParams(t *testing.T, port int, caPEM, security string) *Params {
	t.Helper()
	m := validParams()
	m["servers"] = []any{"127.0.0.1"}
	m["port"], m["security"], m["ca_pem"] = float64(port), security, caPEM
	m["page_size"], m["batch_size"] = 100.0, 100.0
	delete(m, "base_dns")
	p, err := ParseParams(m)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runE2E(t *testing.T, startTLS bool) {
	srv, caPEM := startLDAP(t, startTLS)
	g := []byte{0x3c, 0x2d, 0x1e, 0x0f, 0x5a, 0x4b, 0x78, 0x69, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0}
	srv.computers = entries("PC", 230, 0)
	srv.computers[0].Attrs["objectguid"] = [][]byte{g}
	srv.computers[0].Attrs["objectsid"] = [][]byte{sidBytes(21, 1, 2, 3, 1104)}
	srv.computers[0].Attrs["lastlogontimestamp"] = [][]byte{[]byte("134037792000000000")}
	srv.computers[0].Attrs["whencreated"] = [][]byte{[]byte("20240102030405.0Z")}
	srv.users = entries("user", 20, 5000)
	bs := &batchServer{}
	hs := httptest.NewServer(bs)
	defer hs.Close()
	cl, err := client.New(hs.URL, "cnd_secret", client.Options{InsecureDev: true})
	if err != nil {
		t.Fatal(err)
	}
	sec := SecurityLDAPS
	if startTLS {
		sec = SecurityStartTLS
	}
	p := e2eParams(t, srv.ln.Addr().(*net.TCPAddr).Port, caPEM, sec)
	res := (&Runner{Connect: Connect, Upload: cl}).Run(context.Background(), p)
	if res.Status != "succeeded" || res.Totals.Computers != 230 || res.Totals.Users != 20 || res.Server != "127.0.0.1" {
		t.Fatalf("%+v errs=%v", res, bs.errs)
	}
	if srv.pages != 4 || srv.plainBind || srv.binds != 1 { // 100+100+30 computers, 20 users
		t.Errorf("pages=%d plainBind=%v binds=%d", srv.pages, srv.plainBind, srv.binds)
	}
	if len(bs.errs) > 0 || len(bs.batches) != 3 || !bs.batches[2].Final {
		t.Fatalf("errs=%v batches=%d", bs.errs, len(bs.batches))
	}
	first := bs.batches[0].Computers[0]
	if first.ObjectGUID != "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" || first.ObjectSID != "S-1-5-21-1-2-3-1104" ||
		first.LastLogonTimestamp == nil || first.LastLogonTimestamp.Year() != 2025 || first.WhenCreated == nil {
		t.Errorf("%+v", first)
	}
}

func TestLDAPSEndToEnd(t *testing.T)    { runE2E(t, false) }
func TestStartTLSEndToEnd(t *testing.T) { runE2E(t, true) }

func TestLDAPSRejectsUntrustedCertAndBadPassword(t *testing.T) {
	srv, caPEM := startLDAP(t, false)
	port := srv.ln.Addr().(*net.TCPAddr).Port
	_, otherCA := testCert(t)
	_, err := Connect(context.Background(), e2eParams(t, port, otherCA, SecurityLDAPS))
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("untrusted certificate accepted: %v", err)
	}
	if srv.binds != 0 {
		t.Error("credentials sent to an untrusted server")
	}
	p := e2eParams(t, port, caPEM, SecurityLDAPS)
	p.Password = "wrong-" + testPass
	_, err = Connect(context.Background(), p)
	if err == nil || strings.Contains(err.Error(), p.Password) {
		t.Fatalf("bad password: %v", err)
	}
}

func TestLocateDCs(t *testing.T) {
	old := lookupSRV
	defer func() { lookupSRV = old }()
	lookupSRV = func(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
		if service != "ldap" || proto != "tcp" || name != "dc._msdcs.corp.example.com" {
			return "", nil, fmt.Errorf("unexpected lookup %s %s %s", service, proto, name)
		}
		return "", []*net.SRV{{Target: "dc2.corp.example.com."}, {Target: "dc1.corp.example.com."}}, nil
	}
	p := &Params{Domain: "corp.example.com"}
	if got := LocateDCs(context.Background(), p); strings.Join(got, ",") != "dc2.corp.example.com,dc1.corp.example.com" {
		t.Errorf("%v", got)
	}
	lookupSRV = func(context.Context, string, string, string) (string, []*net.SRV, error) {
		return "", nil, fmt.Errorf("nxdomain")
	}
	if got := LocateDCs(context.Background(), p); len(got) != 1 || got[0] != "corp.example.com" {
		t.Errorf("%v", got)
	}
	p.Servers = []string{"dc9"}
	if got := LocateDCs(context.Background(), p); got[0] != "dc9" {
		t.Errorf("%v", got)
	}
}
