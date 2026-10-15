// Package logx provides a size-capped rotating log file (current + one backup)
// so the agent's own logs can never fill the disk.
package logx

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// MaxBytes is the size at which agent.log is rotated to agent.log.1.
const MaxBytes = 5 * 1024 * 1024

// RotatingFile is an io.Writer appending to path and rotating at max bytes.
type RotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

// Open opens (creating) the log file with owner-only permissions.
func Open(path string, max int64) (*RotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	r := &RotatingFile{path: path, max: max}
	return r, r.open()
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *RotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size+int64(len(p)) > r.max && r.size > 0 {
		r.f.Close()
		_ = os.Remove(r.path + ".1")
		_ = os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

// Close closes the current file.
func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}

// Setup configures slog to write to the log file and, when console is true, stderr.
func Setup(path string, console bool, level slog.Level) (io.Closer, error) {
	var w io.Writer
	var closer io.Closer = io.NopCloser(nil)
	if path != "" {
		rf, err := Open(path, MaxBytes)
		if err != nil {
			return nil, err
		}
		w, closer = rf, rf
	}
	if console {
		if w != nil {
			w = io.MultiWriter(w, os.Stderr)
		} else {
			w = os.Stderr
		}
	}
	if w == nil {
		w = io.Discard
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
	return closer, nil
}
