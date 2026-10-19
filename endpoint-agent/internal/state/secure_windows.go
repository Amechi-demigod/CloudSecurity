//go:build windows

package state

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Protected DACL: full control for LocalSystem and BUILTIN\Administrators only,
// inherited by files and subfolders; nothing inherited from ProgramData.
const stateSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

func defaultPaths() Paths {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	base := filepath.Join(pd, "CNAPP Agent")
	return Paths{StateDir: base, LogDir: filepath.Join(base, "logs")}
}

// SecureDir creates dir and replaces its DACL with SYSTEM + Administrators only.
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return applySDDL(dir)
}

func applySDDL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(stateSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func restrictFile(f *os.File) error { return applySDDL(f.Name()) }

func replaceFile(src, dst string) error {
	from, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// checkPrivilegedOwner requires the file to be owned by LocalSystem or
// BUILTIN\Administrators (what an elevated installer or the service creates).
func checkPrivilegedOwner(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		return nil
	}
	return fmt.Errorf("owned by %s, not SYSTEM or Administrators", owner.String())
}
