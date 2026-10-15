package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServiceArgs(t *testing.T) {
	if got := serviceArgs(Options{}); len(got) != 1 || got[0] != "run" {
		t.Errorf("%v", got)
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "sub", "dst")
	if err := os.WriteFile(src, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o755); err != nil { // replace existing
		t.Fatal(err)
	}
	b, err := os.ReadFile(dst)
	if err != nil || string(b) != "binary" {
		t.Fatalf("%q %v", b, err)
	}
	if err := copyFile(dst, dst, 0o755); err != nil { // same file is a no-op
		t.Fatal(err)
	}
}
