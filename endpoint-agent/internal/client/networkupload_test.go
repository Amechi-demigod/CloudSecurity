package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadNetworkBatch(t *testing.T) {
	var gotPath, gotAuth, gotCT, gotUA, gotBody string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotPath, gotAuth, gotCT, gotBody = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), string(b)
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"detail":"nope"}`)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "col_secret", Options{InsecureDev: true, APIPrefix: "/api/collector", UserAgent: "cnapp-collector/1.6.0"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.UploadNetworkBatch(ctx, "/api/collector/network/scans/s1/results", []byte(`{"seq":0}`)); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/collector/network/scans/s1/results" || gotAuth != "Bearer col_secret" || gotCT != "application/json" ||
		gotBody != `{"seq":0}` || !strings.HasPrefix(gotUA, "cnapp-collector/") {
		t.Errorf("%q %q %q %q %q", gotPath, gotAuth, gotCT, gotBody, gotUA)
	}
	status = 503
	err = c.UploadNetworkBatch(ctx, "/api/collector/network/scans/s1/results", []byte(`{}`))
	var se interface{ StatusCode() int }
	if !errors.As(err, &se) || se.StatusCode() != 503 {
		t.Errorf("err = %v", err)
	}
	for _, bad := range []string{"/api/agent/commands", "/api/collector/../agent", "/api/collector/x?y", "https://evil.test/api/collector/x",
		"/api/collector/a b", `/api/collector\x`} {
		if err := c.UploadNetworkBatch(ctx, bad, nil); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// the endpoint agent's client never uploads network batches
	a, _ := New(srv.URL, "cnd_s", Options{InsecureDev: true})
	if err := a.UploadNetworkBatch(ctx, "/api/collector/network/x", nil); err == nil {
		t.Error("agent client uploaded a network batch")
	}
	if h := c.Host(); !strings.HasPrefix(h, "127.0.0.1:") {
		t.Errorf("host %q", h)
	}
}
