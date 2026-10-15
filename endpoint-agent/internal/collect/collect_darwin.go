//go:build darwin

package collect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/plist"
)

const (
	swVers         = "/usr/bin/sw_vers"
	sysctlBin      = "/usr/sbin/sysctl"
	ioregBin       = "/usr/sbin/ioreg"
	fdesetupBin    = "/usr/bin/fdesetup"
	socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
	spctlBin       = "/usr/sbin/spctl"
	csrutilBin     = "/usr/bin/csrutil"
	sysadminctlBin = "/usr/sbin/sysadminctl"
	dsclBin        = "/usr/bin/dscl"
	whoBin         = "/usr/bin/who"
	plutilBin      = "/usr/bin/plutil"
	xprotectBin    = "/usr/bin/xprotect"
	sudoBin        = "/usr/bin/sudo"
	shortTimeout   = 20 * time.Second
)

func run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := Run(ctx, shortTimeout, name, args...)
	return string(out), err
}

func sysctl(ctx context.Context, key string) string {
	out, err := run(ctx, sysctlBin, "-n", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// readPlist reads an XML or binary plist (binary is converted with plutil).
func readPlist(ctx context.Context, path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m, err := plist.DecodeDict(b)
	if errors.Is(err, plist.ErrBinary) {
		out, cerr := Run(ctx, shortTimeout, plutilBin, "-convert", "xml1", "-o", "-", path)
		if cerr != nil {
			return nil, cerr
		}
		return plist.DecodeDict(out)
	}
	return m, err
}

func platformCollect(ctx context.Context, c collector, o Options) {
	d := &c.r.Device
	c.guard("os", func() error {
		out, err := run(ctx, swVers)
		d.OSName, d.OSVersion, d.OSBuild = parseSwVers(out)
		return err
	})
	c.guard("hardware", func() error {
		d.Manufacturer = "Apple Inc."
		d.CPU = sysctl(ctx, "machdep.cpu.brand_string")
		if n, err := strconv.Atoi(sysctl(ctx, "hw.physicalcpu")); err == nil {
			d.CPUCores = iptr(n)
		}
		if n, err := strconv.ParseInt(sysctl(ctx, "hw.memsize"), 10, 64); err == nil {
			d.MemoryBytes = i64(n)
		}
		d.Model = sysctl(ctx, "hw.model")
		out, err := run(ctx, ioregBin, "-c", "IOPlatformExpertDevice", "-d", "2")
		io := parseIoreg(out)
		d.SerialNumber = io["IOPlatformSerialNumber"]
		if io["model"] != "" {
			d.Model = io["model"]
		}
		return err
	})
	c.guard("uptime", func() error {
		out, err := run(ctx, sysctlBin, "-n", "kern.boottime")
		if err != nil {
			return err
		}
		boot, err := parseBoottime(out)
		if err != nil {
			return err
		}
		d.LastBoot = &boot
		d.UptimeSeconds = i64(int64(time.Since(boot).Seconds()))
		return nil
	})
	c.guard("disks", func() error {
		var st syscall.Statfs_t
		if err := syscall.Statfs("/", &st); err != nil {
			return err
		}
		fs := strings.TrimRight(string(int8sToBytes(st.Fstypename[:])), "\x00")
		d.Disks = []model.Disk{{Mount: "/", Filesystem: fs, SizeBytes: i64(int64(st.Blocks) * int64(st.Bsize)),
			FreeBytes: i64(int64(st.Bavail) * int64(st.Bsize))}}
		return nil
	})
	c.guard("users", func() error {
		users := []string{}
		if u := consoleUser(); u != "" {
			users = append(users, u)
		}
		out, err := run(ctx, whoBin)
		for _, u := range parseWho(out) {
			if !slices.Contains(users, u) {
				users = append(users, u)
			}
		}
		d.LoggedInUsers = users
		return err
	})

	c.posture("disk_encryption", func() (model.PostureCheck, error) {
		out, err := run(ctx, fdesetupBin, "status")
		if err != nil && out == "" {
			return model.PostureCheck{}, err
		}
		return parseFileVault(out), nil
	})
	c.posture("firewall", func() (model.PostureCheck, error) {
		g, err := run(ctx, socketfilterfw, "--getglobalstate")
		if err != nil && g == "" {
			return model.PostureCheck{}, err
		}
		s, _ := run(ctx, socketfilterfw, "--getstealthmode")
		return parseAppFirewall(g, s), nil
	})
	c.posture("gatekeeper", func() (model.PostureCheck, error) {
		out, err := run(ctx, spctlBin, "--status")
		if out == "" {
			return model.PostureCheck{}, err
		}
		return parseGatekeeper(out), nil // spctl exits 1 when disabled
	})
	c.posture("sip", func() (model.PostureCheck, error) {
		out, err := run(ctx, csrutilBin, "status")
		if out == "" {
			return model.PostureCheck{}, err
		}
		return parseSIP(out), nil
	})
	c.posture("antivirus", func() (model.PostureCheck, error) { return xprotectCheck(ctx) })
	c.posture("screen_lock", func() (model.PostureCheck, error) { return screenLockCheck(ctx) })
	c.posture("os_updates", func() (model.PostureCheck, error) {
		m, err := readPlist(ctx, "/Library/Preferences/com.apple.SoftwareUpdate.plist")
		if err != nil {
			return model.PostureCheck{}, err
		}
		return softwareUpdateCheck(m, time.Now()), nil
	})
	c.posture("local_admins", func() (model.PostureCheck, error) {
		out, err := run(ctx, dsclBin, ".", "-read", "/Groups/admin", "GroupMembership")
		if err != nil {
			return model.PostureCheck{}, err
		}
		admins := parseGroupMembership(out)
		return model.Check(model.StatusInfo, fmt.Sprintf("%d account(s) in the admin group", len(admins)),
			map[string]any{"accounts": admins}), nil
	})

	if o.Software {
		c.guard("software", func() error {
			sw, err := applications(ctx)
			c.r.Software = sw
			return err
		})
	}
}

func int8sToBytes(in []int8) []byte {
	b := make([]byte, len(in))
	for i, v := range in {
		b[i] = byte(v)
	}
	return b
}

func consoleUser() string {
	st, err := os.Stat("/dev/console")
	if err != nil {
		return ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid == 0 {
		return ""
	}
	u, err := user.LookupId(strconv.Itoa(int(sys.Uid)))
	if err != nil {
		return ""
	}
	return u.Username
}

func xprotectCheck(ctx context.Context) (model.PostureCheck, error) {
	data := map[string]any{"product": "XProtect"}
	if out, err := run(ctx, xprotectBin, "version"); err == nil {
		if v, inst, ok := parseXProtectVersion(out); ok {
			data["xprotect_version"] = v
			if !inst.IsZero() {
				data["xprotect_installed"] = inst.Format(time.RFC3339)
				data["xprotect_age_days"] = int(time.Since(inst).Hours() / 24)
			}
			return model.Check(model.StatusPass, "XProtect "+v+" (built-in malware protection)", data), nil
		}
	}
	for _, p := range []string{
		"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
		"/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
	} {
		m, err := readPlist(ctx, p)
		if err != nil {
			continue
		}
		v := plist.String(m, "CFBundleShortVersionString")
		data["xprotect_version"] = v
		if st, err := os.Stat(p); err == nil {
			data["xprotect_age_days"] = int(time.Since(st.ModTime()).Hours() / 24)
		}
		return model.Check(model.StatusPass, "XProtect "+v+" (built-in malware protection)", data), nil
	}
	return model.Check(model.StatusFail, "XProtect bundle not found", data), nil
}

func screenLockCheck(ctx context.Context) (model.PostureCheck, error) {
	if m, err := readPlist(ctx, "/Library/Managed Preferences/com.apple.screensaver.plist"); err == nil {
		if c, ok := screenLockFromProfile(m); ok {
			return c, nil
		}
	}
	// sysadminctl reports the setting of the user running it: as root, ask on
	// behalf of the console user (no prompt; status is read-only).
	args := []string{"-screenLock", "status"}
	name := sysadminctlBin
	if u := consoleUser(); u != "" && os.Geteuid() == 0 {
		name, args = sudoBin, append([]string{"-n", "-u", u, sysadminctlBin}, args...)
	}
	out, err := run(ctx, name, args...)
	if strings.TrimSpace(out) == "" {
		if err == nil {
			err = errors.New("no output")
		}
		return model.PostureCheck{}, err
	}
	return parseScreenLock(out), nil
}

// applications reads Info.plist of .app bundles in /Applications (2 levels) and ~/Applications.
func applications(ctx context.Context) ([]model.Software, error) {
	roots := []string{"/Applications", "/Applications/Utilities"}
	if homes, err := filepath.Glob("/Users/*/Applications"); err == nil {
		roots = append(roots, homes...)
	}
	var apps []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(root, e.Name())
			if strings.HasSuffix(e.Name(), ".app") {
				apps = append(apps, p)
			} else if e.IsDir() && root == "/Applications" && e.Name() != "Utilities" {
				// vendor folders such as /Applications/Microsoft Office/...
				if sub, err := filepath.Glob(filepath.Join(p, "*.app")); err == nil {
					apps = append(apps, sub...)
				}
			}
		}
	}
	out := []model.Software{}
	var firstErr error
	for _, a := range apps {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		m, err := readPlist(ctx, filepath.Join(a, "Contents", "Info.plist"))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if sw, ok := appFromInfoPlist(m, a); ok {
			if strings.HasPrefix(a, "/Users/") {
				sw.Source = "user_applications"
			}
			out = append(out, sw)
		}
	}
	if len(out) == 0 && firstErr != nil {
		return out, firstErr
	}
	return out, nil
}

func rawMachineID(ctx context.Context) (string, error) {
	out, err := run(ctx, ioregBin, "-c", "IOPlatformExpertDevice", "-d", "2")
	if id := parseIoreg(out)["IOPlatformUUID"]; id != "" {
		return id, nil
	}
	if err == nil {
		err = errors.New("IOPlatformUUID not found")
	}
	return "", err
}
