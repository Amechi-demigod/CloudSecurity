package collect

import (
	"bufio"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Linux server support (agent 1.7.0). Everything in this file is pure: it
// parses text that collect_linux.go reads from the machine (files and
// read-only commands), so the tests run on any OS against captured fixtures
// in testdata/linux/. Nothing here executes anything or touches the disk.

// ParseOSRelease parses /etc/os-release (KEY=value, optional quotes).
func ParseOSRelease(s string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

var ubuntuLTS = regexp.MustCompile(`^\d\d\.04$`)

// EcosystemFor is the OSV ecosystem of OS packages from the os-release ID and
// VERSION_ID. It must stay identical to backend/app/vulnmatch/inventory.py
// ecosystem_for (the sensor and the agent must agree). "" means OSV has no
// feed for the distribution (Amazon Linux, SUSE, ...): the packages are
// reported but cannot be matched to vulnerabilities.
func EcosystemFor(id, versionID string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	ver := strings.Trim(strings.TrimSpace(versionID), `"`)
	major, _, _ := strings.Cut(ver, ".")
	if id == "" || ver == "" {
		return ""
	}
	switch id {
	case "debian":
		return "Debian:" + major
	case "ubuntu":
		if ubuntuLTS.MatchString(ver) {
			if n, err := strconv.Atoi(ver[:2]); err == nil && n%2 == 0 {
				return "Ubuntu:" + ver + ":LTS"
			}
		}
		return "Ubuntu:" + ver
	case "alpine":
		parts := strings.Split(ver, ".")
		return "Alpine:v" + strings.Join(parts[:min(2, len(parts))], ".")
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "rhel":
		return "Red Hat"
	}
	return ""
}

// PackageFamily is the package manager a distribution uses: "apt", "dnf" or "".
func PackageFamily(osr map[string]string) string {
	ids := strings.Fields(strings.ToLower(osr["ID"] + " " + osr["ID_LIKE"]))
	switch {
	case slices.Contains(ids, "debian") || slices.Contains(ids, "ubuntu"):
		return "apt"
	case slices.ContainsFunc(ids, func(s string) bool {
		return s == "rhel" || s == "fedora" || s == "centos" || s == "rocky" || s == "almalinux" || s == "amzn"
	}):
		return "dnf"
	}
	return ""
}

// ---------------------------------------------------------------- packages

// LinuxPackage is one installed OS package.
type LinuxPackage struct {
	Name          string
	Version       string // binary package version (epoch:version-release for rpm when the epoch is set)
	SourceName    string
	SourceVersion string // dpkg: version of the source package (what Debian / Ubuntu advisories name)
	Arch          string
	Kind          string // deb | rpm
}

var dpkgSource = regexp.MustCompile(`^(\S+)(?: \(([^)]+)\))?$`)

// ParseDpkgStatus parses /var/lib/dpkg/status: installed packages with their
// source package and source version.
func ParseDpkgStatus(s string) []LinuxPackage {
	var out []LinuxPackage
	flush := func(f map[string]string) {
		st := f["Status"]
		if f["Package"] == "" || !strings.HasSuffix(st, " installed") || strings.HasSuffix(st, "not-installed") {
			return
		}
		p := LinuxPackage{Name: f["Package"], Version: f["Version"], SourceName: f["Package"], SourceVersion: f["Version"],
			Arch: f["Architecture"], Kind: "deb"}
		if m := dpkgSource.FindStringSubmatch(strings.TrimSpace(f["Source"])); m != nil {
			p.SourceName = m[1]
			if m[2] != "" {
				p.SourceVersion = m[2]
			}
		}
		out = append(out, p)
	}
	cur := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			flush(cur)
			cur = map[string]string{}
		case l[0] == ' ' || l[0] == '\t':
			// continuation of a multi-line field (Description, Conffiles ...)
		default:
			if k, v, ok := strings.Cut(l, ": "); ok {
				switch k {
				case "Package", "Status", "Version", "Source", "Architecture":
					cur[k] = strings.TrimSpace(v)
				}
			}
		}
	}
	flush(cur)
	return out
}

// RPMQueryFormat is passed to `rpm -qa --queryformat`: a read-only query that
// works on every rpm database format (BerkeleyDB on RHEL 8, sqlite on RHEL 9).
const RPMQueryFormat = `%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`

var srpmName = regexp.MustCompile(`^(.+)-[^-]+-[^-]+\.(?:src|nosrc)\.rpm$`)

// ParseRPMQuery parses `rpm -qa --queryformat RPMQueryFormat` output.
func ParseRPMQuery(s string) []LinuxPackage {
	var out []LinuxPackage
	for _, l := range strings.Split(s, "\n") {
		f := strings.Split(strings.TrimRight(l, "\r"), "\t")
		if len(f) < 5 || f[0] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		ver := f[2] + "-" + f[3]
		if e := strings.TrimSpace(f[1]); e != "" && e != "(none)" && e != "0" {
			ver = e + ":" + ver
		}
		p := LinuxPackage{Name: f[0], Version: ver, SourceName: f[0], SourceVersion: ver, Arch: f[4], Kind: "rpm"}
		if len(f) > 5 {
			if m := srpmName.FindStringSubmatch(strings.TrimSpace(f[5])); m != nil {
				p.SourceName = m[1]
			}
		}
		out = append(out, p)
	}
	return out
}

// SoftwareFromPackages converts packages to the check-in's software list.
// ecosystem is EcosystemFor(os-release); "" leaves the packages unmatched.
func SoftwareFromPackages(pkgs []LinuxPackage, ecosystem string) []model.Software {
	out := make([]model.Software, 0, len(pkgs))
	for _, p := range pkgs {
		src := "dpkg"
		if p.Kind == "rpm" {
			src = "rpm"
		}
		s := model.Software{Name: p.Name, Version: p.Version, Source: src, Ecosystem: ecosystem}
		if p.SourceName != p.Name {
			s.SourceName = p.SourceName
		}
		if p.Kind == "deb" && p.SourceVersion != p.Version {
			s.SourceVersion = p.SourceVersion
		}
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b model.Software) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return out
}

// ---------------------------------------------------------------- systemd

// SystemdUnit is one line of `systemctl list-units`.
type SystemdUnit struct {
	Name, Load, Active, Sub, Description string
}

// ParseListUnits parses `systemctl list-units --type=service --all --plain
// --no-legend --no-pager`.
func ParseListUnits(s string) []SystemdUnit {
	var out []SystemdUnit
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(strings.TrimLeft(l, "●* \t"))
		if len(f) < 4 || !strings.Contains(f[0], ".") {
			continue
		}
		out = append(out, SystemdUnit{Name: f[0], Load: f[1], Active: f[2], Sub: f[3], Description: strings.Join(f[4:], " ")})
	}
	return out
}

// ParseListUnitFiles parses `systemctl list-unit-files --type=service,timer
// --plain --no-legend --no-pager` into unit -> state (enabled, disabled,
// static, masked, indirect, ...).
func ParseListUnitFiles(s string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && strings.Contains(f[0], ".") {
			out[f[0]] = f[1]
		}
	}
	return out
}

// ServicesFromSystemd builds the services inventory. Only loaded, real
// services are listed (not templates, not units that merely failed to load).
func ServicesFromSystemd(units []SystemdUnit, files map[string]string) []model.Service {
	var out []model.Service
	for _, u := range units {
		if !strings.HasSuffix(u.Name, ".service") || strings.HasSuffix(u.Name, "@.service") || u.Load == "not-found" {
			continue
		}
		st := "other"
		switch {
		case u.Active == "active":
			st = "running"
		case u.Active == "inactive", u.Active == "failed":
			st = "stopped"
		case u.Active == "activating":
			st = "start_pending"
		case u.Active == "deactivating":
			st = "stop_pending"
		}
		start := "other"
		switch files[u.Name] {
		case "enabled", "enabled-runtime", "alias":
			start = "auto"
		case "disabled", "masked", "masked-runtime":
			start = "disabled"
		case "static", "indirect", "generated", "transient":
			start = "manual"
		}
		out = append(out, model.Service{Name: u.Name, DisplayName: u.Description, Status: st, StartType: start})
	}
	slices.SortFunc(out, func(a, b model.Service) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// unitState reports whether any of the named units is known to systemd and
// whether any of them is active.
func unitState(units []SystemdUnit, names ...string) (known, active bool) {
	for _, u := range units {
		if slices.Contains(names, u.Name) && u.Load != "not-found" {
			known = true
			active = active || u.Active == "active"
		}
	}
	return known, active
}

// ---------------------------------------------------------------- listening ports

// ListeningPort is one listening socket.
type ListeningPort struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	inode   uint64
}

// ParseProcNet parses /proc/net/tcp, tcp6, udp or udp6. TCP sockets are
// listening in state 0A; UDP sockets are "listening" when unconnected (07).
func ParseProcNet(s, proto string) []ListeningPort {
	var out []ListeningPort
	want := "0A"
	if strings.HasPrefix(proto, "udp") {
		want = "07"
	}
	for i, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 10 || f[3] != want {
			continue
		}
		addr, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, ListeningPort{Proto: proto, Address: procNetAddr(addr), Port: int(port), inode: inode})
	}
	return out
}

// procNetAddr formats the hex address of /proc/net/*: little-endian 32-bit words.
func procNetAddr(h string) string {
	b := make([]byte, 0, 16)
	for i := 0; i+8 <= len(h); i += 8 {
		w, err := strconv.ParseUint(h[i:i+8], 16, 32)
		if err != nil {
			return h
		}
		b = append(b, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	switch len(b) {
	case 4:
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 16:
		allZero := true
		for _, x := range b {
			allZero = allZero && x == 0
		}
		if allZero {
			return "::"
		}
		parts := make([]string, 8)
		for i := range parts {
			parts[i] = strconv.FormatUint(uint64(b[2*i])<<8|uint64(b[2*i+1]), 16)
		}
		return strings.Join(parts, ":")
	}
	return h
}

// ---------------------------------------------------------------- misc inventory

// ParseMeminfoTotal returns MemTotal in bytes from /proc/meminfo.
func ParseMeminfoTotal(s string) (int64, bool) {
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(l, "MemTotal:"); ok {
			if f := strings.Fields(v); len(f) >= 1 {
				if n, err := strconv.ParseInt(f[0], 10, 64); err == nil {
					return n * 1024, true
				}
			}
		}
	}
	return 0, false
}

// ParseCPUInfo returns the CPU model name and the number of logical CPUs from /proc/cpuinfo.
func ParseCPUInfo(s string) (name string, cores int) {
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "processor":
			cores++
		case "model name", "Model", "Hardware":
			if name == "" {
				name = strings.TrimSpace(v)
			}
		}
	}
	return name, cores
}

// ParseUptime returns the seconds in /proc/uptime.
func ParseUptime(s string) (int64, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return int64(v), err == nil && v >= 0
}

// ParseWho returns the distinct user names from `who` output.
func ParseWho(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if f := strings.Fields(l); len(f) > 0 && !slices.Contains(out, f[0]) {
			out = append(out, f[0])
		}
	}
	return out
}

// MountInfo is one mounted filesystem from /proc/mounts.
type MountInfo struct{ Device, Mount, FSType string }

var pseudoFS = map[string]bool{"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true,
	"cgroup": true, "cgroup2": true, "overlay": true, "squashfs": true, "securityfs": true, "debugfs": true,
	"tracefs": true, "configfs": true, "fusectl": true, "mqueue": true, "hugetlbfs": true, "pstore": true,
	"bpf": true, "autofs": true, "binfmt_misc": true, "nsfs": true, "ramfs": true, "rpc_pipefs": true,
	"selinuxfs": true, "efivarfs": true, "fuse.lxcfs": true, "fuse.gvfsd-fuse": true, "devfs": true}

// ParseMounts parses /proc/mounts and keeps real, device-backed filesystems.
func ParseMounts(s string) []MountInfo {
	var out []MountInfo
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || pseudoFS[f[2]] || !strings.HasPrefix(f[0], "/") {
			continue
		}
		mnt := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(f[1])
		if seen[mnt] {
			continue
		}
		seen[mnt] = true
		out = append(out, MountInfo{Device: f[0], Mount: mnt, FSType: f[2]})
	}
	return out
}

// ---------------------------------------------------------------- patches

// APTSimulation is the outcome of `apt-get -s dist-upgrade` (a simulation: it
// installs nothing and never refreshes the package lists).
type APTSimulation struct {
	Pending  int      // upgradable packages
	Security int      // of those, offered by a *-security pocket
	Packages []string // names of the security updates (capped)
}

var aptInst = regexp.MustCompile(`^Inst (\S+) (?:\[[^\]]*\] )?\((\S+) ([^)]*)\)`)

// ParseAPTSimulation parses "Inst pkg [old] (new Origin:Suite/pocket [arch], ...)" lines.
// Packages offered by a security pocket (Ubuntu jammy-security, Debian
// "Debian-Security:12/stable-security", ESM) count as security updates.
func ParseAPTSimulation(s string) APTSimulation {
	var r APTSimulation
	for _, l := range strings.Split(s, "\n") {
		m := aptInst.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		r.Pending++
		origins := strings.ToLower(m[3])
		if strings.Contains(origins, "-security") || strings.Contains(origins, "-esm") || strings.Contains(origins, "esm-") {
			r.Security++
			if len(r.Packages) < 50 {
				r.Packages = append(r.Packages, m[1])
			}
		}
	}
	return r
}

// DNFUpdateinfo is the outcome of `dnf -C updateinfo list --security`.
type DNFUpdateinfo struct {
	Advisories int            // distinct advisories
	Packages   []string       // packages (capped)
	Severities map[string]int // advisories per severity (critical, important, ...)
}

var dnfAdvisory = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)$`)

// ParseDNFUpdateinfo parses `updateinfo list --security`:
// "RLSA-2024:1234  Important/Sec.  openssl-3.0.7-25.el9_3.x86_64".
func ParseDNFUpdateinfo(s string) DNFUpdateinfo {
	r := DNFUpdateinfo{Severities: map[string]int{}}
	adv := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		m := dnfAdvisory.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil || !strings.Contains(m[2], "/") {
			continue // headers, "Last metadata expiration check", blank
		}
		sev, _, _ := strings.Cut(m[2], "/")
		if !adv[m[1]] {
			adv[m[1]] = true
			r.Severities[strings.ToLower(sev)]++
		}
		if len(r.Packages) < 50 && !slices.Contains(r.Packages, m[3]) {
			r.Packages = append(r.Packages, m[3])
		}
	}
	r.Advisories = len(adv)
	return r
}

// RPMVerCmp compares two rpm version strings like librpm's rpmvercmp
// (including '~' pre-release and '^' post-release markers).
func RPMVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isAlpha := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	isAlnum := func(c byte) bool { return isDigit(c) || isAlpha(c) }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ta, tb := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			i++
			j++
			continue
		}
		ca, cb := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ca || cb {
			if i >= len(a) {
				return -1
			}
			if j >= len(b) {
				return 1
			}
			if !ca {
				return 1
			}
			if !cb {
				return -1
			}
			i++
			j++
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		si, sj := i, j
		num := isDigit(a[i])
		if num {
			for i < len(a) && isDigit(a[i]) {
				i++
			}
			for j < len(b) && isDigit(b[j]) {
				j++
			}
		} else {
			for i < len(a) && isAlpha(a[i]) {
				i++
			}
			for j < len(b) && isAlpha(b[j]) {
				j++
			}
		}
		x, y := a[si:i], b[sj:j]
		if y == "" {
			if num {
				return 1
			}
			return -1
		}
		if num {
			x, y = strings.TrimLeft(x, "0"), strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) > len(y) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i >= len(a):
		return -1
	default:
		return 1
	}
}

// NewestKernelRPM returns the newest "version-release.arch" in the output of
// `rpm -q kernel-core --queryformat '%{VERSION}-%{RELEASE}.%{ARCH}\n'`
// ("" when none is installed).
func NewestKernelRPM(s string) string {
	best := ""
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.Contains(l, " ") {
			continue // "package kernel-core is not installed"
		}
		if best == "" || RPMVerCmp(l, best) > 0 {
			best = l
		}
	}
	return best
}
