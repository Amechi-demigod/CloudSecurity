package actions

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Programs reads installed programs (Windows: the registry Uninstall keys)
// and runs uninstallers.
type Programs interface {
	// Lookup returns the Uninstall entry `key` in the given registry view
	// (registry_hklm64 | registry_hklm32) or ErrNotFound.
	Lookup(source, key string) (Program, error)
	// Run executes an uninstaller and returns its exit code and (capped) output.
	Run(ctx context.Context, cmd Cmd) (exitCode int, output string, err error)
}

// Program is one registry Uninstall entry.
type Program struct {
	Key                  string
	Source               string
	DisplayName          string
	DisplayVersion       string
	Publisher            string
	InstallLocation      string
	UninstallString      string
	QuietUninstallString string
	WindowsInstaller     bool
}

// Cmd is an uninstaller to run. Path is always the absolute executable;
// CmdLine (QuietUninstallString only) is passed verbatim as the Windows
// command line, never through a shell.
type Cmd struct {
	Path    string
	Args    []string
	CmdLine string
}

// Uninstall methods.
const (
	MethodMSI   = "msi"
	MethodQuiet = "quiet_uninstall_string"
)

// UninstallSources are the registry views uninstall_software may name.
// Per-user installs (registry_user) are refused: their uninstallers run in
// the user's context, not as the agent's LocalSystem account.
var UninstallSources = []string{"registry_hklm64", "registry_hklm32"}

// AgentProductName is this agent's MSI product name (never uninstalled).
const AgentProductName = "CNAPP Endpoint Agent"

// ErrNoSilentUninstaller: the program has no MSI product code and no QuietUninstallString.
var ErrNoSilentUninstaller = errors.New("no silent uninstaller: this program has no MSI product code and no QuietUninstallString - use a script")

var (
	productCodeRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)
	// Registry key names: anything but a backslash or control characters.
	keyNameRe = regexp.MustCompile(`^[^\\\x00-\x1f\x7f]{1,255}$`)
	// Interpreters a QuietUninstallString may not launch: they run arbitrary
	// code, so the result is not a verifiable silent uninstall.
	scriptHosts = []string{"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
		"rundll32.exe", "regsvr32.exe", "bash.exe", "wsl.exe"}
)

// UninstallParams of an uninstall_software command.
type UninstallParams struct {
	Identifier string // registry key name (the MSI ProductCode for MSI installs)
	Source     string
	Name       string // DisplayName the console showed; must still match
	Version    string
}

// ParseUninstallParams validates uninstall_software parameters.
func ParseUninstallParams(p map[string]any) (UninstallParams, error) {
	var out UninstallParams
	id, ok := str(p, "identifier")
	if !ok || !keyNameRe.MatchString(id) {
		return out, errors.New("identifier must be the program's registry key name")
	}
	src, _ := str(p, "source")
	if !slices.Contains(UninstallSources, src) {
		return out, errors.New("source must be registry_hklm64 or registry_hklm32 (per-user installs cannot be uninstalled by the agent - use a script)")
	}
	name, ok := str(p, "name")
	if !ok || name == "" || len(name) > 255 {
		return out, errors.New("name must be the program's display name (1-255 characters)")
	}
	version, _ := str(p, "version")
	if len(version) > 128 {
		return out, errors.New("version must be at most 128 characters")
	}
	if IsAgentName(name) {
		return out, errors.New("the agent never uninstalls itself (uninstall it with the MSI or the uninstall script)")
	}
	return UninstallParams{Identifier: id, Source: src, Name: name, Version: version}, nil
}

// IsAgentName reports whether a display name is this agent's.
func IsAgentName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n == strings.ToLower(AgentProductName) || strings.HasPrefix(n, "cnapp endpoint agent") ||
		strings.HasPrefix(n, "cnapp agent")
}

// isAgent reports whether an Uninstall entry is this agent (by name or because
// its files or uninstaller live in the agent's directory).
func (m *Manager) isAgent(p Program, exe string) bool {
	if IsAgentName(p.DisplayName) {
		return true
	}
	if m.AgentDir == "" {
		return false
	}
	dir := strings.ToLower(filepath.Clean(m.AgentDir))
	for _, path := range []string{p.InstallLocation, exe} {
		if path == "" {
			continue
		}
		c := strings.ToLower(filepath.Clean(strings.Trim(path, `"`)))
		if c == dir || strings.HasPrefix(c, dir+`\`) || strings.HasPrefix(c, dir+"/") {
			return true
		}
	}
	return false
}

// MsiexecArgs are the arguments of a silent MSI uninstall.
func MsiexecArgs(productCode string) []string {
	return []string{"/x", productCode, "/qn", "/norestart"}
}

func (m *Manager) msiexec() string {
	return filepath.Join(m.SystemRoot, "System32", "msiexec.exe")
}

// Plan picks the uninstaller: MSI by product code, otherwise the
// QuietUninstallString, otherwise ErrNoSilentUninstaller. It never falls back
// to the (interactive) UninstallString.
func (m *Manager) Plan(p Program) (Cmd, string, error) {
	if p.WindowsInstaller && productCodeRe.MatchString(p.Key) {
		return Cmd{Path: m.msiexec(), Args: MsiexecArgs(p.Key)}, MethodMSI, nil
	}
	q := strings.TrimSpace(p.QuietUninstallString)
	if q == "" {
		return Cmd{}, "", ErrNoSilentUninstaller
	}
	exe, err := CommandExe(q)
	if err != nil {
		return Cmd{}, "", err
	}
	base := strings.ToLower(windowsBase(exe))
	if base == "msiexec.exe" {
		exe = m.msiexec() // "MsiExec.exe /X{...} /qn" is usually not an absolute path
	} else if !isAbsWindows(exe) {
		return Cmd{}, "", fmt.Errorf("QuietUninstallString does not start with an absolute path (%s) - use a script", exe)
	}
	if slices.Contains(scriptHosts, base) {
		return Cmd{}, "", fmt.Errorf("QuietUninstallString runs %s, not an uninstaller - use a script", base)
	}
	if !strings.HasSuffix(base, ".exe") {
		return Cmd{}, "", fmt.Errorf("QuietUninstallString does not run an .exe (%s) - use a script", base)
	}
	return Cmd{Path: exe, CmdLine: q}, MethodQuiet, nil
}

// CommandExe extracts the executable from a Windows command line: a quoted
// first token, or (unquoted, possibly with spaces) everything up to the first
// ".exe" followed by a space or the end.
func CommandExe(cmdline string) (string, error) {
	s := strings.TrimSpace(cmdline)
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end <= 0 {
			return "", errors.New("QuietUninstallString has an unterminated quote")
		}
		return s[1 : end+1], nil
	}
	lower := strings.ToLower(s)
	for i := 0; ; {
		j := strings.Index(lower[i:], ".exe")
		if j < 0 {
			break
		}
		end := i + j + 4
		if end == len(s) || s[end] == ' ' || s[end] == '\t' {
			return s[:end], nil
		}
		i = end
	}
	if f := strings.Fields(s); len(f) > 0 {
		return f[0], nil
	}
	return "", errors.New("QuietUninstallString is empty")
}

func windowsBase(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isAbsWindows(p string) bool {
	return len(p) >= 3 && ((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) && p[1] == ':' &&
		(p[2] == '\\' || p[2] == '/')
}

// ExitMeaning maps an uninstaller exit code (Windows Installer conventions,
// which most EXE installers follow) to a command status.
func ExitMeaning(code int) (status, meaning string, reboot bool) {
	switch code {
	case 0:
		return "succeeded", "uninstalled", false
	case 3010:
		return "succeeded", "uninstalled; a restart is required to finish (3010)", true
	case 1641:
		return "succeeded", "uninstalled; the uninstaller started a restart (1641)", true
	case 1605:
		return "succeeded", "the product is not installed (1605): nothing to remove", false
	case 1614:
		return "succeeded", "the product is already uninstalled (1614)", false
	case 1618:
		return "failed", "another installation is in progress (1618); try again later", false
	case 1602:
		return "failed", "the uninstall was cancelled (1602)", false
	case 1603:
		return "failed", "fatal error during uninstall (1603); see the Windows Installer log / event log", false
	case 1625:
		return "failed", "the uninstall is forbidden by system policy (1625)", false
	}
	return "failed", fmt.Sprintf("the uninstaller exited with code %d", code), false
}

func (m *Manager) uninstall(ctx context.Context, p UninstallParams) Result {
	prog, err := m.Programs.Lookup(p.Source, p.Identifier)
	if errors.Is(err, ErrNotFound) {
		return Result{Status: "succeeded", Output: fmt.Sprintf("%s is not installed (no registry entry): nothing to remove", p.Name),
			Data: map[string]any{"name": p.Name, "verified": true, "already_removed": true}, Refresh: true}
	}
	if err != nil {
		return failed("reading the registry entry of %s: %v", p.Name, err)
	}
	if !sameFold(prog.DisplayName, p.Name) {
		return rejected("the registry entry %s is now %q, not %q: refresh the software inventory and try again",
			p.Identifier, prog.DisplayName, p.Name)
	}
	cmd, method, err := m.Plan(prog)
	if err != nil {
		return Result{Status: "rejected", Output: err.Error(),
			Data: map[string]any{"name": prog.DisplayName, "error_code": "ERR_NO_SILENT_UNINSTALLER"}}
	}
	if m.isAgent(prog, cmd.Path) {
		return rejected("the agent never uninstalls itself (uninstall it with the MSI or the uninstall script)")
	}
	rctx, cancel := context.WithTimeout(ctx, m.UninstallTime)
	defer cancel()
	code, output, err := m.Programs.Run(rctx, cmd)
	data := map[string]any{"name": prog.DisplayName, "version": prog.DisplayVersion, "method": method}
	if err != nil {
		if errors.Is(rctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return Result{Status: "failed", Output: fmt.Sprintf("the uninstaller did not finish within %s and was stopped", m.UninstallTime),
				Data: data, Refresh: true}
		}
		return Result{Status: "failed", Output: fmt.Sprintf("starting the uninstaller: %v", err), Data: data}
	}
	status, meaning, reboot := ExitMeaning(code)
	data["reboot_required"] = reboot
	out := fmt.Sprintf("%s %s: %s", prog.DisplayName, prog.DisplayVersion, meaning)
	if status == "succeeded" {
		// Verify: the entry must disappear (some EXE uninstallers hand off to a
		// child process and return at once, so wait a little). A pending
		// restart may legitimately keep it until the device restarts.
		gone := m.wait(ctx, m.VerifyWait, func() bool {
			_, err := m.Programs.Lookup(p.Source, p.Identifier)
			return errors.Is(err, ErrNotFound)
		})
		data["verified"] = gone
		if !gone && !reboot {
			status = "failed"
			out += "; but the program is still registered as installed"
		} else if !gone {
			out += "; it stays listed until the device restarts"
		}
	}
	if s := strings.TrimSpace(output); s != "" {
		out += "\n" + s
	}
	return Result{Status: status, Output: out, ExitCode: &code, Data: data, Refresh: true}
}
