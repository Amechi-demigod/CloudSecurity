package netscan

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/client"
)

// The real collector client against an httptest server that fails the first
// attempt of every batch: retries re-send the identical body and the server
// (idempotent on seq) ends up with each batch exactly once.
func TestUploadRetriesOverHTTPAreIdempotent(t *testing.T) {
	var mu sync.Mutex
	attempts := map[int]int{}
	stored := map[int][]byte{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var batch Batch
		if err := json.Unmarshal(b, &batch); err != nil || r.Header.Get("Authorization") != "Bearer col_secret" ||
			r.URL.Path != "/api/collector/network/scans/s/results" {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		attempts[batch.Seq]++
		if attempts[batch.Seq] == 1 {
			w.WriteHeader(502)
			return
		}
		if old, ok := stored[batch.Seq]; ok && string(old) != string(b) {
			w.WriteHeader(409)
			return
		}
		stored[batch.Seq] = b
		w.WriteHeader(200)
	}))
	defer srv.Close()
	c, err := client.New(srv.URL, "col_secret", client.Options{InsecureDev: true, APIPrefix: "/api/collector"})
	if err != nil {
		t.Fatal(err)
	}
	e := fastEnv()
	e.Ping = func(context.Context, netip.Addr, time.Duration) (bool, error) { return true, nil }
	res := e.Run(context.Background(), params(t, testNet, nil), "/api/collector/network/scans/s/results", c)
	mu.Lock()
	defer mu.Unlock()
	if res.Failed || res.Batches != 2 || len(stored) != 2 || attempts[0] != 2 || attempts[1] != 2 {
		t.Errorf("%+v attempts=%v stored=%d", res, attempts, len(stored))
	}
	var fin Batch
	_ = json.Unmarshal(stored[1], &fin)
	if !fin.Final || fin.Summary == nil || fin.Summary.Alive != 768 {
		t.Errorf("%+v", fin)
	}
}
