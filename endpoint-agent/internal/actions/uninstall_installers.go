package actions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
)

// Recognised EXE installer families whose uninstaller has a documented silent
// mode. Anything else is refused: a plain UninstallString usually opens a
// wizard, and the agent (LocalSystem, no desktop) would hang on it.
const (
	MethodInno = "inno"
	MethodNSIS = "nsis"
)

var (
	// Inno Setup names its uninstaller unins000.exe, unins001.exe, ...
	innoNameRe = regexp.MustCompile(`(?i)^unins\d{3}\.exe$`)
	// NSIS embeds these in the stub (.rdata) and in the data header it
	// appends ("NullsoftInst" follows the 0xDEADBEEF flag word).
	nsisSignatures = [][]byte{[]byte("NullsoftInst"), []byte("Nullsoft Install System")}
)

// nsisScanLimit bounds how much of an uninstaller is read looking for the
// NSIS signature (the stub is a few tens of KB and the header follows it).
const nsisScanLimit = 1 << 20

// InnoSilentArgs are appended to an Inno Setup uninstaller.
var InnoSilentArgs = []string{"/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"}

// FileHasNSISSignature reports whether the executable at path carries the
// Nullsoft signature within its first nsisScanLimit bytes. The file name is
// never enough to call something NSIS.
func FileHasNSISSignature(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, nsisScanLimit))
	if err != nil && len(buf) == 0 {
		return false
	}
	for _, sig := range nsisSignatures {
		if bytes.Contains(buf, sig) {
			return true
		}
	}
	return false
}

// PlanInstallerUninstall decides whether p's UninstallString is an Inno Setup
// or NSIS uninstaller and builds its silent command. It is pure (no OS calls
// except through isNSIS, which tests replace), so it runs on any OS.
// It returns ErrNoSilentUninstaller when the installer is not positively
// identified.
//
//   - Inno Setup: the entry has Inno's own registry values, or the uninstaller
//     is named unins###.exe. Run with InnoSilentArgs (exec argument list).
//   - NSIS: isNSIS(exe) must confirm the Nullsoft signature. Run with /S and
//     _?=<install dir>. Without _?= an NSIS uninstaller copies itself to %TEMP%,
//     starts the copy and exits at once, so the agent could neither wait for it
//     nor apply the timeout. NSIS requires _?= to be the last parameter and
//     reads it unquoted (the rest of the command line), so the NSIS command is
//     passed as a verbatim command line instead of Go-quoted arguments.
//
// Arguments already present in the UninstallString are kept.
func PlanInstallerUninstall(p Program, isNSIS func(path string) bool) (Cmd, string, error) {
	u := strings.TrimSpace(p.UninstallString)
	if u == "" {
		return Cmd{}, "", ErrNoSilentUninstaller
	}
	exe, err := CommandExe(u)
	if err != nil {
		return Cmd{}, "", errors.New(strings.Replace(err.Error(), "QuietUninstallString", "UninstallString", 1))
	}
	if !isAbsWindows(exe) {
		return Cmd{}, "", ErrNoSilentUninstaller
	}
	base := windowsBase(exe)
	lower := strings.ToLower(base)
	if slices.Contains(scriptHosts, lower) || !strings.HasSuffix(lower, ".exe") || strings.ContainsAny(exe, `"`) {
		return Cmd{}, "", ErrNoSilentUninstaller
	}
	rest := u[len(exe):]
	if strings.HasPrefix(u, `"`) {
		rest = u[len(exe)+2:]
	}
	args := splitWindowsArgs(rest)

	if p.InnoSetupVersion != "" || p.InnoAppPath != "" || innoNameRe.MatchString(base) {
		return Cmd{Path: exe, Args: append(args, InnoSilentArgs...)}, MethodInno, nil
	}
	if isNSIS != nil && isNSIS(exe) {
		dir := strings.TrimRight(exe[:len(exe)-len(base)], `\/`)
		kept := args[:0:0]
		for _, a := range args {
			if strings.EqualFold(a, "/S") || strings.HasPrefix(a, "_?=") {
				continue // replaced below; _?= must come last
			}
			kept = append(kept, a)
		}
		parts := []string{quoteWindowsArg(exe)}
		for _, a := range append(kept, "/S") {
			parts = append(parts, quoteWindowsArg(a))
		}
		return Cmd{Path: exe, CmdLine: strings.Join(parts, " ") + " _?=" + dir}, MethodNSIS, nil
	}
	return Cmd{}, "", ErrNoSilentUninstaller
}

// splitWindowsArgs splits a command-line tail on spaces and tabs, honouring
// double quotes (which are removed).
func splitWindowsArgs(s string) []string {
	var out []string
	var cur strings.Builder
	in, has := false, false
	for _, r := range s {
		switch {
		case r == '"':
			in, has = !in, true
		case (r == ' ' || r == '\t') && !in:
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
			has = true
		}
	}
	if has {
		out = append(out, cur.String())
	}
	return out
}

func quoteWindowsArg(a string) string {
	if a == "" || strings.ContainsAny(a, " \t") {
		return fmt.Sprintf(`"%s"`, a)
	}
	return a
}
