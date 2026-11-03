package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

const (
	dirRun   = "0123456789abcdef0123456789abcdef"
	dirToken = "tok_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_xyz"
	dirPass  = "S3cret-Passw0rd!"
)

type emptyDir struct{ release chan struct{} }

func (e *emptyDir) Server() string { return "dc1" }
func (e *emptyDir) Close() error   { return nil }
func (e *emptyDir) Search(ctx context.Context, _, _ string, _ []string, _ int, _ func(directory.Entry) error) error {
	if e.release != nil {
		select {
		case <-e.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func dirParams() map[string]any {
	return map[string]any{"source_id": "fedcba9876543210fedcba9876543210", "run_id": dirRun,
		"domain": "corp.example.com", "port": 636.0, "security": "ldaps", "scopes": []any{"computers"},
		"auth": "simple", "upload_path": directory.UploadPrefix + dirRun + "/batches", "upload_token": dirToken,
		"credential": map[string]any{"username": "svc", "password": dirPass}}
}

func TestDirectorySyncRunsInBackground(t *testing.T) {
	a, f := setup(t)
	dir := &emptyDir{release: make(chan struct{})}
	a.DirectoryConnect = func(context.Context, *directory.Params) (directory.Searcher, error) { return dir, nil }
	f.commands = []model.Command{command("c-dir", "directory_sync", dirParams())}
	if err := a.PollCommands(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	status, out := f.results["c-dir"], f.outputs["c-dir"]
	f.mu.Unlock()
	if status != "succeeded" || !strings.Contains(out, "started") || strings.Contains(out, dirPass) ||
		strings.Contains(out, dirToken) {
		t.Fatalf("%s: %q", status, out)
	}
	if !a.DirectorySyncBusy() {
		t.Fatal("sync should still be running (polling was not blocked)")
	}
	// A second sync while one runs is refused.
	f.mu.Lock()
	f.commands = []model.Command{command("c-dir2", "directory_sync", dirParams())}
	f.mu.Unlock()
	_ = a.PollCommands(context.Background())
	f.mu.Lock()
	if f.results["c-dir2"] != "failed" {
		t.Errorf("concurrent sync: %q", f.results["c-dir2"])
	}
	f.mu.Unlock()
	close(dir.release)
	if !a.WaitDirectorySync(5 * time.Second) {
		t.Fatal("sync did not finish")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.dirBatches) != 1 || f.dirBatches[0] != directory.UploadPrefix+dirRun+"/batches|"+dirToken+"|gzip" {
		t.Fatalf("%v", f.dirBatches)
	}
}

func TestDirectorySyncRejectsBadParams(t *testing.T) {
	a, f := setup(t)
	p := dirParams()
	p["security"], p["port"] = "ldaps", 389.0 // plain-text port without StartTLS
	f.commands = []model.Command{command("c-bad", "directory_sync", p)}
	_ = a.PollCommands(context.Background())
	if f.results["c-bad"] != "rejected" || strings.Contains(f.outputs["c-bad"], dirPass) {
		t.Fatalf("%q %q", f.results["c-bad"], f.outputs["c-bad"])
	}
}
