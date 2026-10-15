package logx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "agent.log")
	r, err := Open(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := r.Write([]byte(strings.Repeat("x", 30) + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	a, _ := os.Stat(p)
	b, err := os.Stat(p + ".1")
	if err != nil || a.Size() > 100 || b.Size() > 100 {
		t.Fatalf("rotation failed: %v %v", a, err)
	}
}
