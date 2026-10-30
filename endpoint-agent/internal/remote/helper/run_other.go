//go:build !windows

package helper

import (
	"fmt"
	"os"
	"runtime"
)

// Run is Windows-only for now (a macOS helper is future work).
func Run(pipe string) int {
	fmt.Fprintf(os.Stderr, "remote-helper is not supported on %s (Windows only)\n", runtime.GOOS)
	return 2
}
