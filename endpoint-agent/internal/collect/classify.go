package collect

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Device classification (model.Classification): workstation / server /
// domain controller, form factor, virtualisation and cloud. Everything is
// read locally and offline: the OS product type, SMBIOS / DMI strings and the
// CPUID hypervisor leaf. Cloud metadata services (IMDS) are never called.
// The parsers and the decision logic live here (OS-independent, tested
// against fixtures); classify_<os>.go only gather the raw facts.

// FirmwareFacts are the SMBIOS / DMI values classification uses. Linux reads
// them from /sys/class/dmi/id, Windows from the raw SMBIOS table
// (GetSystemFirmwareTable 'RSMB', parsed by ParseSMBIOS).
type FirmwareFacts struct {
	SysVendor       string // type 1 manufacturer
	ProductName     string // type 1 product name
	ProductVersion  string // type 1 version
	ProductUUID     string // type 1 UUID, lower-case 8-4-4-4-12
	BIOSVendor      string // type 0 vendor
	BoardAssetTag   string // type 2 asset tag
	ChassisType     int    // type 3 type (lock bit stripped); 0 = unknown
	ChassisAssetTag string // type 3 asset tag
	// CPUIDVendor is the hypervisor vendor signature from CPUID leaf
	// 0x40000000 ("VMwareVMware", "Microsoft Hv", "KVMKVMKVM", ...); "" when
	// the hypervisor-present bit is clear or CPUID is unavailable (arm64).
	CPUIDVendor string
}

// azureAssetTag is the chassis asset tag every Azure VM carries.
const azureAssetTag = "7783-7084-3265-9085-8269-3286-77"

var ec2InstanceID = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)

// ChassisFormFactor maps an SMBIOS chassis type (DSP0134 7.4.1) to a form factor.
func ChassisFormFactor(t int) string {
	switch t {
	case 8, 9, 10, 14, 31, 32: // portable, laptop, notebook, sub notebook, convertible, detachable
		return model.FormLaptop
	case 11, 30: // hand held, tablet
		return model.FormTablet
	case 3, 4, 5, 6, 7, 13, 15, 16, 24, 34, 35, 36: // desktop .. all-in-one, mini / stick PC
		return model.FormDesktop
	case 17, 23, 25, 28, 29: // main server chassis, rack mount, multi-system, blade
		return model.FormServer
	case 0, 2: // not reported / unknown
		return ""
	default:
		return model.FormOther
	}
}

// virtualFromStrings recognises a hypervisor from SMBIOS vendor / product
// strings. "" when the strings look like physical hardware.
func virtualFromStrings(f FirmwareFacts) string {
	s := strings.ToLower(strings.Join([]string{f.SysVendor, f.ProductName, f.ProductVersion, f.BIOSVendor}, "|"))
	switch {
	case strings.Contains(s, "vmware"):
		return "vmware"
	case strings.Contains(s, "virtualbox") || strings.Contains(s, "innotek"):
		return "virtualbox"
	case strings.Contains(s, "parallels"):
		return "parallels"
	case strings.Contains(s, "microsoft corporation") && strings.Contains(s, "virtual machine"):
		return "hyper-v"
	case strings.Contains(s, "xen"):
		return "xen"
	case strings.Contains(s, "amazon ec2"):
		if strings.HasSuffix(strings.ToLower(f.ProductName), ".metal") {
			return "" // bare-metal EC2 instance
		}
		return "nitro"
	case strings.Contains(s, "google compute engine"), strings.Contains(s, "qemu"), strings.Contains(s, "kvm"),
		strings.Contains(s, "bochs"), strings.Contains(s, "openstack"), strings.Contains(s, "rhev"),
		strings.Contains(s, "proxmox"), strings.Contains(s, "nutanix ahv"):
		return "kvm"
	case strings.Contains(s, "apple virtualization") || strings.Contains(s, "virtualmac"):
		return "apple"
	}
	return ""
}

// hypervisorFromCPUID maps a CPUID leaf 0x40000000 vendor signature.
func hypervisorFromCPUID(sig string) string {
	switch strings.TrimRight(sig, "\x00 ") {
	case "":
		return ""
	case "VMwareVMware":
		return "vmware"
	case "Microsoft Hv":
		return "hyper-v"
	case "KVMKVMKVM", "TCGTCGTCGTCG", "Linux KVM Hv":
		return "kvm"
	case "XenVMMXenVMM":
		return "xen"
	case "VBoxVBoxVBox":
		return "virtualbox"
	case " lrpepyh  vr", "prl hyperv":
		return "parallels"
	default:
		return "other"
	}
}

// classifyFirmware derives form factor, virtualisation and cloud from
// firmware facts. SMBIOS strings are authoritative. The CPUID signature only
// confirms or fills in: "Microsoft Hv" alone is ignored because physical
// Windows machines with virtualisation-based security (Credential Guard,
// HVCI) run as the Hyper-V root partition and report it too.
func classifyFirmware(f FirmwareFacts, c *model.Classification) {
	if f.ChassisType > 0 {
		t := f.ChassisType
		c.ChassisType = &t
	}
	hv := virtualFromStrings(f)
	if cpu := hypervisorFromCPUID(f.CPUIDVendor); hv == "" && cpu != "" && cpu != "hyper-v" {
		hv = cpu
	}
	virtual := hv != ""
	c.IsVirtual = &virtual
	c.Hypervisor = hv
	if virtual {
		// Virtual chassis types are arbitrary (Hyper-V says "desktop").
		c.FormFactor = model.FormOther
	} else {
		c.FormFactor = ChassisFormFactor(f.ChassisType)
	}
	vendor := strings.ToLower(f.SysVendor + "|" + f.BIOSVendor)
	switch {
	case strings.EqualFold(strings.TrimSpace(f.ChassisAssetTag), azureAssetTag):
		c.CloudProvider = "azure"
		c.CloudInstanceID = f.ProductUUID // the Azure VM id (vmId)
	case strings.Contains(vendor, "amazon ec2") || strings.HasPrefix(strings.ToLower(f.ProductUUID), "ec2"):
		c.CloudProvider = "aws"
		// Nitro instances carry the instance id in the baseboard asset tag;
		// older Xen instances do not expose it offline.
		if tag := strings.ToLower(strings.TrimSpace(f.BoardAssetTag)); ec2InstanceID.MatchString(tag) {
			c.CloudInstanceID = tag
		}
	case strings.EqualFold(strings.TrimSpace(f.ProductName), "Google Compute Engine") || strings.Contains(vendor, "google"):
		// GCE exposes no instance id in SMBIOS; the server links by name.
		c.CloudProvider = "gcp"
	case strings.EqualFold(strings.TrimSpace(f.ChassisAssetTag), "OracleCloud.com"):
		c.CloudProvider = "oci"
	}
}

// LinuxRole is the Linux role heuristic: a Linux host is a server unless it
// is clearly a user machine - a physical laptop / tablet / desktop chassis, or
// a graphical boot target (systemd default.target -> graphical.target, which
// desktop distributions use and server installs do not).
func LinuxRole(c *model.Classification, graphicalTarget bool) (role, source string) {
	physical := c.IsVirtual == nil || !*c.IsVirtual
	switch {
	case physical && (c.FormFactor == model.FormLaptop || c.FormFactor == model.FormTablet || c.FormFactor == model.FormDesktop):
		return model.RoleWorkstation, "chassis"
	case graphicalTarget:
		return model.RoleWorkstation, "graphical_target"
	default:
		return model.RoleServer, "linux_default"
	}
}

// WindowsRole maps HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions
// ProductType (the OS product type RtlGetVersion also reports).
func WindowsRole(productType string) string {
	switch strings.ToLower(strings.TrimSpace(productType)) {
	case "winnt":
		return model.RoleWorkstation
	case "servernt":
		return model.RoleServer
	case "lanmannt":
		return model.RoleDomainController
	}
	return ""
}

// MacClassification classifies a Mac from its model identifier (hw.model /
// ioreg "model"), whether a battery is present and kern.hv_vmm_present.
// Macs are always workstations.
func MacClassification(modelID string, hasBattery, vmmPresent bool) *model.Classification {
	c := &model.Classification{Role: model.RoleWorkstation, RoleSource: "macos"}
	m := strings.ToLower(modelID)
	hv := ""
	switch {
	case strings.Contains(m, "vmware"):
		hv = "vmware"
	case strings.Contains(m, "parallels"):
		hv = "parallels"
	case strings.Contains(m, "virtualmac"):
		hv = "apple"
	case vmmPresent:
		hv = "other"
	}
	virtual := hv != ""
	c.IsVirtual = &virtual
	c.Hypervisor = hv
	switch {
	case virtual:
		c.FormFactor = model.FormOther
	case hasBattery || strings.HasPrefix(m, "macbook"):
		c.FormFactor = model.FormLaptop
	case modelID != "":
		c.FormFactor = model.FormDesktop
	}
	return c
}

// ParseSMBIOS parses the raw SMBIOS table returned by GetSystemFirmwareTable
// ('RSMB'): an 8-byte RawSMBIOSData header (calling method, major, minor,
// DMI revision, uint32 length) followed by the structure table.
func ParseSMBIOS(raw []byte) (FirmwareFacts, error) {
	var f FirmwareFacts
	if len(raw) < 8 {
		return f, fmt.Errorf("smbios: short header (%d bytes)", len(raw))
	}
	major, minor := raw[1], raw[2]
	n := int(binary.LittleEndian.Uint32(raw[4:8]))
	tbl := raw[8:]
	if n < len(tbl) {
		tbl = tbl[:n]
	}
	for len(tbl) >= 4 {
		typ, length := tbl[0], int(tbl[1])
		if length < 4 || length > len(tbl) {
			break
		}
		formatted := tbl[:length]
		// The string set follows the formatted area and ends with a double NUL.
		rest := tbl[length:]
		end := 0
		for end+1 < len(rest) && (rest[end] != 0 || rest[end+1] != 0) {
			end++
		}
		strs := strings.Split(string(rest[:end]), "\x00")
		str := func(off int) string {
			if off >= len(formatted) {
				return ""
			}
			i := int(formatted[off])
			if i == 0 || i > len(strs) {
				return ""
			}
			return strings.TrimSpace(strs[i-1])
		}
		switch typ {
		case 0:
			f.BIOSVendor = str(4)
		case 1:
			f.SysVendor, f.ProductName, f.ProductVersion = str(4), str(5), str(6)
			if len(formatted) >= 0x18 {
				f.ProductUUID = smbiosUUID(formatted[8:24], major, minor)
			}
		case 2:
			if f.BoardAssetTag == "" {
				f.BoardAssetTag = str(8)
			}
		case 3:
			if f.ChassisType == 0 && len(formatted) > 5 {
				f.ChassisType = int(formatted[5] & 0x7f)
				f.ChassisAssetTag = str(8)
			}
		case 127: // end of table
			return f, nil
		}
		if end+2 > len(rest) {
			break
		}
		tbl = rest[end+2:]
	}
	return f, nil
}

// smbiosUUID formats the type 1 UUID. Since SMBIOS 2.6 the first three
// fields are little-endian (what Linux shows in product_uuid); all-0x00 and
// all-0xFF mean "not set".
func smbiosUUID(b []byte, major, minor byte) string {
	allZero, allFF := true, true
	for _, x := range b {
		allZero = allZero && x == 0
		allFF = allFF && x == 0xff
	}
	if allZero || allFF {
		return ""
	}
	u := append([]byte(nil), b...)
	if major > 2 || (major == 2 && minor >= 6) {
		u[0], u[1], u[2], u[3] = u[3], u[2], u[1], u[0]
		u[4], u[5] = u[5], u[4]
		u[6], u[7] = u[7], u[6]
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// NormalizeUUID lower-cases a DMI product_uuid; "" for placeholders.
func NormalizeUUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 || s == "00000000-0000-0000-0000-000000000000" || s == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		return ""
	}
	return s
}

// ReadDMIDir reads Linux DMI facts from a /sys/class/dmi/id style directory
// (product_uuid and board_asset_tag are root-only; the agent runs as root).
func ReadDMIDir(dir string) FirmwareFacts {
	rd := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	f := FirmwareFacts{
		SysVendor: rd("sys_vendor"), ProductName: rd("product_name"), ProductVersion: rd("product_version"),
		ProductUUID: NormalizeUUID(rd("product_uuid")), BIOSVendor: rd("bios_vendor"),
		BoardAssetTag: rd("board_asset_tag"), ChassisAssetTag: rd("chassis_asset_tag"),
	}
	f.ChassisType, _ = strconv.Atoi(rd("chassis_type"))
	return f
}

// GraphicalDefaultTarget reports whether the systemd default target under
// root (normally "/") is graphical.target.
func GraphicalDefaultTarget(root string) bool {
	for _, p := range []string{"etc/systemd/system/default.target", "lib/systemd/system/default.target",
		"usr/lib/systemd/system/default.target"} {
		if t, err := os.Readlink(filepath.Join(root, p)); err == nil {
			return filepath.Base(t) == "graphical.target"
		}
	}
	return false
}
