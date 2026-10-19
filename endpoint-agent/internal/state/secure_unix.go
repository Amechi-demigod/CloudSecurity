//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func defaultPaths() Paths {
	if isDarwin {
		return Paths{StateDir: "/Library/Application Support/CNAPP Agent", LogDir: "/Library/Logs/CNAPP Agent"}
	}
	return Paths{StateDir: "/var/lib/cnapp-agent", LogDir: "/var/log/cnapp-agent"}
}

// SecureDir creates dir (0700, owned by the running user: root for the daemon).
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

func restrictFile(f *os.File) error { return f.Chmod(0o600) }

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	return os.Chmod(filepath.Clean(dst), 0o600)
}

// checkPrivilegedOwner requires root ownership and no group/other write access.
func checkPrivilegedOwner(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine the file owner")
	}
	if st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, not root", st.Uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("writable by group or others (mode %v)", info.Mode().Perm())
	}
	return nil
}
