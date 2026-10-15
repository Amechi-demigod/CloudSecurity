package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

// MaxBundleBytes caps the compressed log bundle (the server default is 5 MiB).
const MaxBundleBytes = 4 << 20

// BuildLogs creates the collect_logs bundle: the agent's own logs (tail-capped),
// its redacted state, and a fresh inventory/posture snapshot without the
// software list. No user files are ever included.
func (a *Agent) BuildLogs(ctx context.Context) ([]byte, error) {
	st := a.State().Redacted()
	report := a.Collect(ctx, collect.Options{Software: false})
	info := map[string]any{"agent_version": version.Version, "created_at": time.Now().UTC(), "os": runtime.GOOS,
		"arch": runtime.GOARCH}
	limits := []int64{2 << 20, 1 << 20}
	for attempt := 0; attempt < 4; attempt++ {
		files := []bundleFile{}
		add := func(name string, v any) {
			b, _ := json.MarshalIndent(v, "", "  ")
			files = append(files, bundleFile{name, b})
		}
		add("bundle.json", info)
		add("state.json", st)
		add("inventory.json", report)
		logFile := a.Paths.LogFile()
		for i, p := range []string{logFile, logFile + ".1"} {
			if limits[i] <= 0 {
				continue
			}
			if b, err := tail(p, limits[i]); err == nil {
				files = append(files, bundleFile{fmt.Sprintf("logs/agent.log%s", map[int]string{0: "", 1: ".1"}[i]), b})
			}
		}
		gz, err := tarGz(files)
		if err != nil {
			return nil, err
		}
		if len(gz) <= MaxBundleBytes {
			return gz, nil
		}
		limits[0], limits[1] = limits[0]/2, 0
	}
	return nil, fmt.Errorf("log bundle exceeds %d bytes", MaxBundleBytes)
}

type bundleFile struct {
	name string
	data []byte
}

func tail(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		if _, err := f.Seek(st.Size()-max, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, max))
}

func tarGz(files []bundleFile) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	now := time.Now()
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.data)), ModTime: now}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
