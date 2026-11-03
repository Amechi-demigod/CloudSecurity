package directory

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDir is an in-memory Searcher: entries per filter, served in pages.
type fakeDir struct {
	computers, users []Entry
	pages            int           // pages served
	block            chan struct{} // if set, Search blocks until ctx is done
	searchErr        error
}

func (f *fakeDir) Server() string { return "dc1.corp.example.com" }
func (f *fakeDir) Close() error   { return nil }
func (f *fakeDir) Search(ctx context.Context, base, filter string, attrs []string, pageSize int,
	fn func(Entry) error) error {
	if f.searchErr != nil {
		return f.searchErr
	}
	if f.block != nil {
		close(f.block)
		<-ctx.Done()
		return ctx.Err()
	}
	src := f.computers
	if filter == UserFilter {
		src = f.users
	}
	for i := 0; i < len(src); i += pageSize {
		f.pages++
		for _, e := range src[i:min(i+pageSize, len(src))] {
			if err := fn(e); err != nil {
				return err
			}
		}
	}
	return nil
}

func guidN(n int) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[8:], uint64(n)+1)
	return b
}

func entries(prefix string, n, offset int) []Entry {
	out := make([]Entry, n)
	for i := range out {
		out[i] = Entry{DN: fmt.Sprintf("CN=%s%d,DC=corp,DC=example,DC=com", prefix, i), Attrs: map[string][][]byte{
			"objectguid": {guidN(offset + i)}, "cn": {[]byte(fmt.Sprintf("%s%d", prefix, i))},
			"samaccountname": {[]byte(fmt.Sprintf("%s%d", prefix, i))}, "useraccountcontrol": {[]byte("512")},
		}}
	}
	return out
}

type statusErr int

func (s statusErr) Error() string   { return fmt.Sprintf("server returned %d", int(s)) }
func (s statusErr) StatusCode() int { return int(s) }

// fakeUploader decodes every batch.
type fakeUploader struct {
	mu      sync.Mutex
	batches []Batch
	fail    []error // returned for the next calls, in order
	ctxErrs []error // ctx.Err() at each call
}

func (u *fakeUploader) UploadDirectoryBatch(ctx context.Context, path, token string, gz []byte) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.ctxErrs = append(u.ctxErrs, ctx.Err())
	if len(u.fail) > 0 {
		err := u.fail[0]
		u.fail = u.fail[1:]
		if err != nil {
			return err
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	var b Batch
	if err := json.NewDecoder(zr).Decode(&b); err != nil {
		return err
	}
	if path != UploadPrefix+testRun+"/batches" || token != testToken {
		return errors.New("bad path / token")
	}
	u.batches = append(u.batches, b)
	return nil
}

func params(t *testing.T, mut func(m map[string]any)) *Params {
	t.Helper()
	m := validParams()
	m["page_size"], m["batch_size"] = 100.0, 100.0
	delete(m, "base_dns")
	if mut != nil {
		mut(m)
	}
	p, err := ParseParams(m)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func runner(dir Searcher, up *fakeUploader, connErr error) *Runner {
	return &Runner{Upload: up, RetryDelays: []time.Duration{time.Millisecond, time.Millisecond},
		FinalTimeout: time.Second,
		Connect: func(context.Context, *Params) (Searcher, error) {
			if connErr != nil {
				return nil, connErr
			}
			return dir, nil
		}}
}

func TestRunBatchesAndFinal(t *testing.T) {
	dir := &fakeDir{computers: entries("PC", 250, 0), users: entries("u", 30, 1000)}
	up := &fakeUploader{}
	res := runner(dir, up, nil).Run(context.Background(), params(t, nil))
	if res.Status != "succeeded" || res.Totals.Computers != 250 || res.Totals.Users != 30 || res.Truncated {
		t.Fatalf("%+v", res)
	}
	if dir.pages != 4 { // 3 computer pages + 1 user page
		t.Errorf("pages %d", dir.pages)
	}
	// 280 objects / batch 100: seq 0, 1 full; final seq 2 with the remaining 80.
	if len(up.batches) != 3 {
		t.Fatalf("%d batches", len(up.batches))
	}
	for i, b := range up.batches {
		if b.Seq != i || b.Final != (i == 2) {
			t.Errorf("batch %d: seq %d final %v", i, b.Seq, b.Final)
		}
	}
	f := up.batches[2]
	if f.Status != "succeeded" || f.Totals == nil || f.Totals.Computers != 250 || f.Totals.Users != 30 ||
		len(f.Computers)+len(f.Users) != 80 || f.Server != "dc1.corp.example.com" {
		t.Fatalf("final %+v", f)
	}
	if len(up.batches[0].Computers) != 100 || up.batches[0].Users == nil {
		t.Error("batch shape")
	}
}

func TestRunMaxObjectsCap(t *testing.T) {
	up := &fakeUploader{}
	p := params(t, func(m map[string]any) { m["max_objects"] = 150.0 })
	res := runner(&fakeDir{computers: entries("PC", 250, 0), users: entries("u", 30, 1000)}, up, nil).
		Run(context.Background(), p)
	if res.Status != "succeeded" || !res.Truncated || res.Totals.Computers != 150 || res.Totals.Users != 0 {
		t.Fatalf("%+v", res)
	}
	f := up.batches[len(up.batches)-1]
	if !f.Final || !f.Truncated || f.Totals.Computers != 150 {
		t.Fatalf("%+v", f)
	}
}

func TestRunDedupesOverlappingBases(t *testing.T) {
	up := &fakeUploader{}
	p := params(t, func(m map[string]any) {
		m["base_dns"] = []any{"DC=corp,DC=example,DC=com", "OU=Laptops,DC=corp,DC=example,DC=com"}
		m["scopes"] = []any{"computers"}
	})
	res := runner(&fakeDir{computers: entries("PC", 50, 0)}, up, nil).Run(context.Background(), p)
	if res.Totals.Computers != 50 {
		t.Fatalf("%+v", res)
	}
}

func TestRunConnectErrorIsRedacted(t *testing.T) {
	up := &fakeUploader{}
	res := runner(nil, up, fmt.Errorf("bind failed for password %s (token %s)", testPass, testToken)).
		Run(context.Background(), params(t, nil))
	if res.Status != "failed" || len(up.batches) != 1 {
		t.Fatalf("%+v %d", res, len(up.batches))
	}
	f := up.batches[0]
	if !f.Final || f.Status != "failed" || strings.Contains(f.Error, testPass) || strings.Contains(f.Error, testToken) ||
		!strings.Contains(f.Error, "[redacted]") {
		t.Fatalf("%+v", f)
	}
	if strings.Contains(res.Error, testPass) {
		t.Error("result leaks the password")
	}
}

func TestRunCancellationSendsFinalWithFreshContext(t *testing.T) {
	up := &fakeUploader{}
	dir := &fakeDir{block: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result)
	go func() { done <- runner(dir, up, nil).Run(ctx, params(t, nil)) }()
	<-dir.block
	cancel()
	res := <-done
	if res.Status != "failed" || len(up.batches) != 1 {
		t.Fatalf("%+v", res)
	}
	f := up.batches[0]
	if !f.Final || f.Status != "failed" || !strings.Contains(f.Error, "cancelled") || len(f.Computers) != 0 {
		t.Fatalf("%+v", f)
	}
	if up.ctxErrs[0] != nil {
		t.Error("final batch sent with a cancelled context")
	}
}

func TestRunTimeout(t *testing.T) {
	up := &fakeUploader{}
	p := params(t, nil)
	p.Timeout = 20 * time.Millisecond
	res := runner(&fakeDir{block: make(chan struct{})}, up, nil).Run(context.Background(), p)
	if res.Status != "failed" || !strings.Contains(up.batches[0].Error, "timed out") {
		t.Fatalf("%+v %+v", res, up.batches)
	}
}

func TestRunUploadRetriesAndStops(t *testing.T) {
	// 503 then success: retried, same seq.
	up := &fakeUploader{fail: []error{statusErr(503)}}
	res := runner(&fakeDir{computers: entries("PC", 10, 0)}, up, nil).Run(context.Background(), params(t, nil))
	if res.Status != "succeeded" || len(up.batches) != 1 || up.batches[0].Seq != 0 {
		t.Fatalf("%+v %+v", res, up.batches)
	}
	// 409 (run cancelled on the server): stop at once, no final batch.
	up = &fakeUploader{fail: []error{statusErr(409)}}
	res = runner(&fakeDir{computers: entries("PC", 250, 0)}, up, nil).Run(context.Background(), params(t, nil))
	if res.Status != "failed" || len(up.batches) != 0 || len(up.ctxErrs) != 1 {
		t.Fatalf("%+v calls=%d", res, len(up.ctxErrs))
	}
	// Network errors beyond the retry budget: give up.
	netErr := errors.New("connection refused")
	up = &fakeUploader{fail: []error{netErr, netErr, netErr}}
	res = runner(&fakeDir{computers: entries("PC", 10, 0)}, up, nil).Run(context.Background(), params(t, nil))
	if res.Status != "failed" || len(up.ctxErrs) != 3 {
		t.Fatalf("%+v calls=%d", res, len(up.ctxErrs))
	}
}

func TestRunSearchError(t *testing.T) {
	up := &fakeUploader{}
	res := runner(&fakeDir{searchErr: errors.New("LDAP Result Code 32 \"No Such Object\"")}, up, nil).
		Run(context.Background(), params(t, nil))
	if res.Status != "failed" || !strings.Contains(up.batches[0].Error, "No Such Object") {
		t.Fatalf("%+v", up.batches)
	}
}
