package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestEnrollConfigRoundTripAndProtection(t *testing.T) {
	p := Resolve(t.TempDir())
	if _, err := LoadEnrollConfig(p); err != ErrNoEnrollConfig {
		t.Fatalf("expected ErrNoEnrollConfig, got %v", err)
	}
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCert(t)}))
	c := &EnrollConfig{ServerURL: "https://cnapp.example.com/", Token: "cne_abcdefghijklmnop", CAPEM: ca}
	if err := SaveEnrollConfig(p, c); err != nil {
		t.Fatal(err)
	}
	got, err := LoadEnrollConfig(p)
	if err != nil || got.ServerURL != "https://cnapp.example.com" || got.Token != c.Token || !strings.Contains(got.CAPEM, "BEGIN CERTIFICATE") {
		t.Fatalf("got %+v %v", got, err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p.EnrollFile()); st.Mode().Perm() != 0o600 {
			t.Fatalf("enroll.json mode %v", st.Mode().Perm())
		}
	}
	if err := Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.EnrollFile()); !os.IsNotExist(err) {
		t.Fatal("purge kept enroll.json")
	}
}

func TestEnrollConfigValidation(t *testing.T) {
	bad := map[string]string{
		"http":       `{"server_url":"http://cnapp.example.com","token":"cne_abcdefghijk"}`,
		"no token":   `{"server_url":"https://cnapp.example.com","token":""}`,
		"bad token":  `{"server_url":"https://cnapp.example.com","token":"cnd_abcdefghijk"}`,
		"bad ca":     `{"server_url":"https://cnapp.example.com","token":"cne_abcdefghijk","ca_pem":"nope"}`,
		"unknown":    `{"server_url":"https://cnapp.example.com","token":"cne_abcdefghijk","insecure_dev":true}`,
		"version":    `{"version":2,"server_url":"https://cnapp.example.com","token":"cne_abcdefghijk"}`,
		"creds":      `{"server_url":"https://u:p@cnapp.example.com","token":"cne_abcdefghijk"}`,
		"not json":   `server=x`,
		"key in pem": `{"server_url":"https://cnapp.example.com","token":"cne_abcdefghijk","ca_pem":"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}`,
	}
	for name, doc := range bad {
		if _, err := ParseEnrollConfig([]byte(doc)); err == nil {
			t.Errorf("%s: accepted %s", name, doc)
		}
	}
	if _, err := ParseEnrollConfig([]byte(`{"version":1,"server_url":"https://10.10.11.57","token":"cne_abc-DEF_123456"}`)); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

func TestDecodeCAB64(t *testing.T) {
	der := testCert(t)
	pemText := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, in := range map[string]string{
		"pem":     base64.StdEncoding.EncodeToString(pemText),
		"der":     base64.StdEncoding.EncodeToString(der),
		"wrapped": strings.Join(strings.SplitAfterN(base64.StdEncoding.EncodeToString(pemText), "", 3), "\n "),
	} {
		got, err := DecodeCAB64(in)
		if err != nil || !strings.Contains(got, "BEGIN CERTIFICATE") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := ParseCABundle([]byte(got)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := DecodeCAB64("  "); err != nil || got != "" {
		t.Error("empty CA must be allowed (publicly trusted server)")
	}
	if _, err := DecodeCAB64("!!notbase64"); err == nil {
		t.Error("garbage accepted")
	}
}
