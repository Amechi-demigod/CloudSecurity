//go:build linux

package collect

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Linux server collection (agent 1.7.0, servers only). Everything is read-only:
// files under /etc, /proc, /sys, /var/lib and fixed, absolute-path commands run
// without a shell and with a timeout. The agent never installs, removes or
// upgrades a package, never refreshes a package cache and never changes a
// setting. See docs/DEVICE_MANAGEMENT.md ("Linux servers").

const (
	linuxShort = 20 * time.Second
	linuxLong  = 90 * time.Second
	maxFile    = 8 << 20
)

// find returns the first existing path.
func find(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func readText(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile))
	return string(b), err
}

func readTrim(path string) string {
	s, _ := readText(path)
	return strings.TrimSpace(s)
}

// runBin runs a fixed absolute path (skipped when the binary does not exist).
func runBin(ctx context.Context, timeout time.Duration, paths []string, args ...string) (string, error) {
	bin := find(paths...)
	if bin == "" {
		return "", fmt.Errorf("%s is not installed", filepath.Base(paths[0]))
	}
	out, err := Run(ctx, timeout, bin, args...)
	return string(out), err
}

var (
	binSystemctl = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	binSSHD      = []string{"/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"}
	binAptGet    = []string{"/usr/bin/apt-get"}
	binDNF       = []string{"/usr/bin/dnf"}
	binRPM       = []string{"/usr/bin/rpm", "/bin/rpm"}
	binLsblk     = []string{"/usr/bin/lsblk", "/bin/lsblk"}
	binUFW       = []string{"/usr/sbin/ufw"}
	binFirewallD = []string{"/usr/bin/firewall-cmd"}
	binNft       = []string{"/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"}
	binIptables  = []string{"/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables"}
	binTimedatec = []string{"/usr/bin/timedatectl", "/bin/timedatectl"}
	binWho       = []string{"/usr/bin/who", "/bin/who"}
)

func platformCollect(ctx context.Context, c collector, o Options) {
	// Command output is parsed in English; the agent never shows it localised.
	_ = os.Setenv("LC_ALL", "C")
	_ = os.Setenv("LANG", "C")
	d := &c.r.Device
	osr := map[string]string{}
	c.guard("os", func() error {
		s, err := readText("/etc/os-release")
		if err != nil {
			s, err = readText("/usr/lib/os-release")
		}
		osr = ParseOSRelease(s)
		d.OSName = osr["PRETTY_NAME"]
		if d.OSName == "" {
			d.OSName = "Linux"
		}
		d.OSVersion = osr["VERSION_ID"]
		d.OSBuild = readTrim("/proc/sys/kernel/osrelease") // kernel release
		return err
	})
	d.DirectoryJoin = linuxJoin(ctx, d.Hostname)
	var cloud string
	c.guard("classification", func() error {
		d.Classification = linuxClassification()
		cloud = d.Classification.CloudProvider
		return nil
	})
	linuxHardware(c, d)

	// One systemctl round trip feeds the services inventory and several checks.
	var units []SystemdUnit
	unitFiles := map[string]string{}
	haveSystemd := false
	c.guard("services", func() error {
		// (Run returns stderr as the output of a failed command, so success is judged by the error, not the text.)
		if _, serr := os.Stat("/run/systemd/system"); serr != nil {
			return errors.New("systemd is not running on this machine: services, timers and service-based checks are unknown")
		}
		out, err := runBin(ctx, linuxShort, binSystemctl, "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager")
		if err != nil {
			return fmt.Errorf("systemd services unavailable: %w", err)
		}
		haveSystemd = true
		units = ParseListUnits(out)
		if uf, err := runBin(ctx, linuxShort, binSystemctl, "list-unit-files", "--type=service,timer", "--plain", "--no-legend", "--no-pager"); err == nil {
			unitFiles = ParseListUnitFiles(uf)
		}
		if svcs := ServicesFromSystemd(units, unitFiles); len(svcs) > 0 {
			c.r.Services = svcs[:min(len(svcs), 2000)]
		}
		return nil
	})

	family := PackageFamily(osr)
	eco := EcosystemFor(osr["ID"], osr["VERSION_ID"])
	var pkgs []LinuxPackage
	c.guard("packages", func() error {
		var err error
		switch family {
		case "apt":
			var s string
			if s, err = readText("/var/lib/dpkg/status"); err == nil {
				pkgs = ParseDpkgStatus(s)
			}
		case "dnf":
			var out string
			if out, err = runBin(ctx, linuxLong, binRPM, "-qa", "--queryformat", RPMQueryFormat); err == nil {
				pkgs = ParseRPMQuery(out)
			}
		default:
			err = errors.New("unsupported distribution: no dpkg or rpm package database is read")
		}
		if err == nil && o.Software {
			c.r.Software = SoftwareFromPackages(pkgs, eco)
		}
		return err
	})
	pkgSet := map[string]bool{}
	for _, p := range pkgs {
		pkgSet[p.Name] = true
	}
	c.posture("package_inventory", func() (model.PostureCheck, error) {
		return packageInventoryCheck(family, eco, len(pkgs), osr), nil
	})

	now := time.Now()
	c.posture("security_updates", func() (model.PostureCheck, error) {
		return securityUpdates(ctx, family, now)
	})
	c.posture("reboot_required", func() (model.PostureCheck, error) {
		return rebootRequired(ctx, family), nil
	})
	c.posture("auto_updates", func() (model.PostureCheck, error) {
		f := AutoUpdateFacts{Family: family, UnitFiles: unitFiles, Packages: pkgSet}
		if !haveSystemd {
			return model.Unknown("systemd is not available, so timers cannot be read", nil), nil
		}
		f.APTPeriodic = readDirText("/etc/apt/apt.conf.d")
		f.DNFAutomatic, _ = readText("/etc/dnf/automatic.conf")
		return AutoUpdatesCheck(f), nil
	})
	c.posture("firewall", func() (model.PostureCheck, error) {
		return FirewallCheck(firewallStates(ctx), cloud), nil
	})
	c.posture("disk_encryption", func() (model.PostureCheck, error) {
		out, err := runBin(ctx, linuxShort, binLsblk, "--json", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINT")
		if err != nil {
			return model.Unknown("lsblk could not list the volumes", err), nil
		}
		mounts, perr := ParseLsblkJSON(out)
		if perr != nil {
			return model.Unknown("lsblk output could not be read", perr), nil
		}
		return DiskEncryptionCheck(mounts, cloud), nil
	})
	var sshCfg map[string]string
	var sshErr error
	sshRan := false
	sshd := func() {
		if sshRan {
			return
		}
		sshRan = true
		if find(binSSHD...) == "" {
			sshErr = errNoSSHD
			return
		}
		out, err := runBin(ctx, linuxShort, binSSHD, "-T")
		if err != nil && !strings.Contains(out, "permitrootlogin") {
			sshErr = err
			return
		}
		sshCfg = ParseSSHDConfig(out)
	}
	sshCheck := func(fn func(map[string]string) model.PostureCheck) (model.PostureCheck, error) {
		sshd()
		switch {
		case errors.Is(sshErr, errNoSSHD):
			return model.Check(model.StatusInfo, "The OpenSSH server (sshd) is not installed.", map[string]any{"evidence": ev("sshd not found")}), nil
		case sshErr != nil:
			return model.Unknown("sshd -T could not read the effective configuration", sshErr), nil
		}
		return fn(sshCfg), nil
	}
	c.posture("ssh_root_login", func() (model.PostureCheck, error) { return sshCheck(SSHRootLoginCheck) })
	c.posture("ssh_password_login", func() (model.PostureCheck, error) { return sshCheck(SSHPasswordCheck) })
	c.posture("admin_accounts", func() (model.PostureCheck, error) { return adminAccounts(), nil })
	c.posture("endpoint_protection", func() (model.PostureCheck, error) {
		if !haveSystemd {
			return model.Unknown("systemd is not available, so services cannot be read", nil), nil
		}
		return EndpointProtectionCheck(units, pkgSet), nil
	})
	c.posture("mandatory_access_control", func() (model.PostureCheck, error) {
		f := MACFacts{AppArmorOn: readTrim("/sys/module/apparmor/parameters/enabled")}
		if _, err := os.Stat("/sys/fs/selinux"); err == nil {
			f.SELinuxPresent = true
			f.SELinuxEnforce = readTrim("/sys/fs/selinux/enforce")
		}
		f.AppArmorProfs, _ = readText("/sys/kernel/security/apparmor/profiles")
		return MACCheck(f), nil
	})
	c.posture("audit_logging", func() (model.PostureCheck, error) {
		if !haveSystemd {
			return model.Unknown("systemd is not available, so services cannot be read", nil), nil
		}
		return AuditCheck(units, pkgSet), nil
	})
	c.posture("time_sync", func() (model.PostureCheck, error) {
		out, err := runBin(ctx, linuxShort, binTimedatec, "show")
		if err != nil {
			return model.Unknown("timedatectl could not report the clock state", err), nil
		}
		return TimeSyncCheck(ParseTimedatectlShow(out), units), nil
	})
	c.posture("listening_ports", func() (model.PostureCheck, error) { return listeningPorts(), nil })
}

var errNoSSHD = errors.New("sshd not installed")

func packageInventoryCheck(family, eco string, n int, osr map[string]string) model.PostureCheck {
	data := map[string]any{"package_manager": family, "packages": n, "ecosystem": eco, "os_id": osr["ID"], "os_version_id": osr["VERSION_ID"]}
	if eco == "" {
		reason := "OSV.dev has no vulnerability feed for " + orStr(osr["PRETTY_NAME"], "this distribution") +
			": packages are reported but not matched to vulnerabilities."
		if osr["ID"] == "amzn" {
			reason = "OSV.dev has no Amazon Linux feed: packages are reported but not matched to vulnerabilities (Not matched)."
		}
		data["vulnerability_matching"], data["reason"] = "not_matched", reason
		data["evidence"] = ev(fmt.Sprintf("%d packages", n), "ecosystem: none")
		return model.Check(model.StatusInfo, reason, data)
	}
	data["vulnerability_matching"] = "osv"
	data["evidence"] = ev(fmt.Sprintf("%d packages", n), "OSV ecosystem "+eco)
	return model.Check(model.StatusInfo, fmt.Sprintf("%d packages, matched to vulnerabilities through OSV (%s).", n, eco), data)
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func linuxHardware(c collector, d *model.DeviceInfo) {
	c.guard("hardware", func() error {
		dmi := func(n string) string {
			v := readTrim("/sys/class/dmi/id/" + n)
			switch strings.ToLower(v) {
			case "", "not specified", "to be filled by o.e.m.", "default string", "none", "system serial number":
				return ""
			}
			return v
		}
		d.Manufacturer, d.Model, d.SerialNumber = dmi("sys_vendor"), dmi("product_name"), dmi("product_serial")
		if s, err := readText("/proc/cpuinfo"); err == nil {
			name, cores := ParseCPUInfo(s)
			d.CPU = name
			if cores > 0 {
				d.CPUCores = iptr(cores)
			}
		}
		if s, err := readText("/proc/meminfo"); err == nil {
			if n, ok := ParseMeminfoTotal(s); ok {
				d.MemoryBytes = i64(n)
			}
		}
		return nil
	})
	c.guard("uptime", func() error {
		s, err := readText("/proc/uptime")
		if err != nil {
			return err
		}
		if up, ok := ParseUptime(s); ok {
			d.UptimeSeconds = i64(up)
			boot := time.Now().Add(-time.Duration(up) * time.Second).UTC().Truncate(time.Second)
			d.LastBoot = &boot
		}
		return nil
	})
	c.guard("disks", func() error {
		s, err := readText("/proc/mounts")
		if err != nil {
			return err
		}
		d.Disks = []model.Disk{}
		for _, m := range ParseMounts(s) {
			var st syscall.Statfs_t
			if syscall.Statfs(m.Mount, &st) != nil || st.Blocks == 0 {
				continue
			}
			d.Disks = append(d.Disks, model.Disk{Mount: m.Mount, Filesystem: m.FSType,
				SizeBytes: i64(int64(st.Blocks) * int64(st.Bsize)), FreeBytes: i64(int64(st.Bavail) * int64(st.Bsize))})
		}
		return nil
	})
	c.guard("users", func() error {
		out, err := runBin(context.Background(), linuxShort, binWho)
		if err == nil {
			d.LoggedInUsers = ParseWho(out)
		}
		return err
	})
}

// readDirText concatenates the small regular files of a directory (apt.conf.d).
func readDirText(dir string) string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var b strings.Builder
	for _, e := range ents {
		if e.IsDir() || b.Len() > 256<<10 {
			continue
		}
		if s, err := readText(filepath.Join(dir, e.Name())); err == nil && len(s) < 64<<10 {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func newest(paths []string) time.Time {
	var t time.Time
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && st.ModTime().After(t) {
			t = st.ModTime()
		}
	}
	return t
}

func securityUpdates(ctx context.Context, family string, now time.Time) (model.PostureCheck, error) {
	f := PatchFacts{Family: family, Now: now}
	switch family {
	case "apt":
		lists, _ := filepath.Glob("/var/lib/apt/lists/*Release")
		f.CacheMod = newest(append(lists, "/var/lib/apt/periodic/update-success-stamp"))
		// A simulation: nothing is installed and the package lists are not refreshed.
		out, err := runBin(ctx, linuxLong, binAptGet, "-s", "-o", "Debug::NoLocking=1", "dist-upgrade")
		if err != nil && !strings.Contains(out, "Inst ") && !strings.Contains(out, "0 upgraded") {
			return model.Unknown("apt-get could not simulate the upgrade", err), nil
		}
		r := ParseAPTSimulation(out)
		f.APT = &r
	case "dnf":
		repo, _ := filepath.Glob("/var/cache/dnf/*/repodata/repomd.xml")
		f.CacheMod = newest(repo)
		// -C: cache only. dnf is never allowed to download or rewrite metadata here.
		out, err := runBin(ctx, linuxLong, binDNF, "-C", "-q", "updateinfo", "list", "--security")
		if err != nil {
			return model.Unknown("dnf could not list security updates from its existing cache", fmt.Errorf("%w: %s", err, firstLine(out))), nil
		}
		r := ParseDNFUpdateinfo(out)
		f.DNF = &r
	}
	return SecurityUpdatesCheck(f), nil
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

func rebootRequired(ctx context.Context, family string) model.PostureCheck {
	f := RebootFacts{Family: family, RunningKernel: readTrim("/proc/sys/kernel/osrelease")}
	switch family {
	case "apt":
		if _, err := os.Stat("/var/run/reboot-required"); err == nil {
			f.RebootFlag = true
			if s, err := readText("/var/run/reboot-required.pkgs"); err == nil {
				for _, l := range strings.Split(s, "\n") {
					if l = strings.TrimSpace(l); l != "" && !slices.Contains(f.RebootPkgs, l) {
						f.RebootPkgs = append(f.RebootPkgs, l)
					}
				}
			}
		}
	case "dnf":
		out, _ := runBin(ctx, linuxShort, binRPM, "-q", "kernel-core", "kernel", "--queryformat", `%{VERSION}-%{RELEASE}.%{ARCH}\n`)
		f.NewestKernel = NewestKernelRPM(out)
	}
	return RebootCheck(f)
}

func firewallStates(ctx context.Context) []FirewallState {
	var out []FirewallState
	if s, err := runBin(ctx, linuxShort, binUFW, "status", "verbose"); s != "" || err == nil {
		if st, ok := ParseUFWStatus(s); ok {
			out = append(out, st)
		}
	}
	if find(binFirewallD...) != "" {
		state, _ := runBin(ctx, linuxShort, binFirewallD, "--state")
		var zone, target string
		if strings.TrimSpace(state) == "running" {
			zone, _ = runBin(ctx, linuxShort, binFirewallD, "--get-default-zone")
			target, _ = runBin(ctx, linuxShort, binFirewallD, "--zone="+strings.TrimSpace(zone), "--get-target")
		}
		out = append(out, ParseFirewalld(state, zone, target))
	}
	if s, err := runBin(ctx, linuxShort, binNft, "list", "ruleset"); err == nil {
		if st, ok := ParseNftRuleset(s); ok {
			out = append(out, st)
		}
	}
	if s, err := runBin(ctx, linuxShort, binIptables, "-S"); err == nil {
		if st, ok := ParseIptablesS(s); ok {
			out = append(out, st)
		}
	}
	return out
}

func adminAccounts() model.PostureCheck {
	passwd, err := readText("/etc/passwd")
	if err != nil {
		return model.Unknown("could not read /etc/passwd", err)
	}
	f := AdminFacts{Passwd: ParsePasswd(passwd)}
	if g, err := readText("/etc/group"); err == nil {
		f.Groups = ParseGroup(g)
	}
	// Only whether each password field is empty is kept; the hashes are never stored or sent.
	if sh, err := readText("/etc/shadow"); err != nil {
		f.ShadowErr = err.Error()
	} else {
		f.EmptyPassword = ParseShadowEmpty(sh)
	}
	f.Sudoers, f.SudoersErr = readSudoers("/etc/sudoers", 0, new(int))
	return AdminAccountsCheck(f)
}

// readSudoers reads a sudoers file and the files it includes (depth and file
// count are bounded; sudo ignores include-directory names with '.' or '~').
func readSudoers(path string, depth int, files *int) ([]SudoRule, string) {
	if depth > 4 || *files > 200 {
		return nil, "include depth or file count limit reached"
	}
	*files++
	s, err := readText(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ""
		}
		return nil, err.Error()
	}
	sf := ParseSudoers(s)
	rules, errs := sf.Rules, []string{}
	sub := func(p string) {
		r, e := readSudoers(p, depth+1, files)
		rules = append(rules, r...)
		if e != "" {
			errs = append(errs, e)
		}
	}
	for _, inc := range sf.Includes {
		if !filepath.IsAbs(inc) {
			inc = filepath.Join(filepath.Dir(path), inc)
		}
		sub(inc)
	}
	for _, dir := range sf.Dirs {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(filepath.Dir(path), dir)
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err.Error())
			}
			continue
		}
		for _, e := range ents {
			if n := e.Name(); !e.IsDir() && !strings.Contains(n, ".") && !strings.HasSuffix(n, "~") {
				sub(filepath.Join(dir, n))
			}
		}
	}
	return rules, strings.Join(errs, "; ")
}

// listeningPorts lists TCP / UDP listeners from /proc/net with the owning process name.
func listeningPorts() model.PostureCheck {
	var all []ListeningPort
	for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if s, err := readText("/proc/net/" + p); err == nil {
			all = append(all, ParseProcNet(s, p)...)
		}
	}
	if len(all) == 0 {
		return model.Check(model.StatusInfo, "No listening ports.", map[string]any{"ports": []ListeningPort{}, "port_numbers": []int{}, "evidence": []string{}})
	}
	owners := socketOwners()
	seen := map[string]bool{}
	var ports []ListeningPort
	nums := map[int]bool{}
	for _, p := range all {
		p.Process = owners[p.inode]
		key := fmt.Sprintf("%s/%s/%d", p.Proto[:3], p.Address, p.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		nums[p.Port] = true
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Proto < ports[j].Proto
	})
	numbers := make([]int, 0, len(nums))
	for n := range nums {
		numbers = append(numbers, n)
	}
	sort.Ints(numbers)
	strs := make([]string, 0, len(numbers))
	for _, n := range numbers[:min(len(numbers), 40)] {
		strs = append(strs, strconv.Itoa(n))
	}
	return model.Check(model.StatusInfo, fmt.Sprintf("%s listening: %s.", plural(len(numbers), "port", "ports"), strings.Join(strs, ", ")),
		map[string]any{"ports": ports[:min(len(ports), 80)], "port_numbers": numbers[:min(len(numbers), 200)],
			"evidence": []string{strings.Join(strs, ", ")}})
}

// socketOwners maps socket inodes to process names by reading /proc/<pid>/fd links.
func socketOwners() map[uint64]string {
	out := map[uint64]string{}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range pids {
		fds, err := os.ReadDir(p + "/fd")
		if err != nil {
			continue
		}
		name := ""
		for _, fd := range fds {
			l, err := os.Readlink(p + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			if name == "" {
				name = readTrim(p + "/comm")
			}
			out[ino] = name
		}
	}
	return out
}

func rawMachineID(context.Context) (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if s := readTrim(p); s != "" {
			return s, nil
		}
	}
	return "", errors.New("no /etc/machine-id")
}

// linuxJoin reports the realmd (AD / Kerberos) membership, if any. Missing
// realmd or a failure is not an error: most Linux hosts are not joined.
func linuxJoin(ctx context.Context, hostname string) *model.DirectoryJoin {
	out, err := runBin(ctx, linuxShort, []string{"/usr/sbin/realm", "/usr/bin/realm"}, "list")
	if err != nil {
		return nil
	}
	return ParseRealmList(out, hostname)
}

// linuxClassification: DMI facts, CPUID and the role heuristic (LinuxRole).
// Cloud provider (AWS / Azure / GCP) comes from DMI only: no metadata service is called.
func linuxClassification() *model.Classification {
	f := ReadDMIDir("/sys/class/dmi/id")
	f.CPUIDVendor = cpuidHypervisor()
	c := &model.Classification{}
	classifyFirmware(f, c)
	// The Linux agent supports servers only (no desktops): the role is not guessed.
	c.Role, c.RoleSource = model.RoleServer, "linux_agent"
	return c
}
