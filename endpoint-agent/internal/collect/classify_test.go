package collect

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

func dmi(t *testing.T, name, cpuid string) *model.Classification {
	t.Helper()
	f := ReadDMIDir(filepath.Join("..", "..", "testdata", "dmi", name))
	if f.SysVendor == "" {
		t.Fatalf("fixture %s not found", name)
	}
	f.CPUIDVendor = cpuid
	c := &model.Classification{}
	classifyFirmware(f, c)
	return c
}

func TestClassifyDMIFixtures(t *testing.T) {
	cases := []struct {
		name, cpuid               string
		virtual                   bool
		hv, form, cloud, instance string
		role                      string
	}{
		{"azure", "Microsoft Hv", true, "hyper-v", "other", "azure", "9b6c0f38-5f2e-4a51-b8f0-2e4c1d3a7b10", "server"},
		{"aws_nitro", "KVMKVMKVM", true, "nitro", "other", "aws", "i-0abc123def4567890", "server"},
		{"aws_metal", "", false, "", "server", "aws", "i-0fedcba9876543210", "server"},
		{"gcp", "KVMKVMKVM", true, "kvm", "other", "gcp", "", "server"},
		{"vmware", "VMwareVMware", true, "vmware", "other", "", "", "server"},
		{"kvm", "KVMKVMKVM", true, "kvm", "other", "", "", "server"},
		{"laptop", "", false, "", "laptop", "", "", "workstation"},
		// Physical Windows with VBS reports "Microsoft Hv": still physical.
		{"desktop", "Microsoft Hv", false, "", "desktop", "", "", "workstation"},
		{"rack", "", false, "", "server", "", "", "server"},
	}
	for _, tc := range cases {
		c := dmi(t, tc.name, tc.cpuid)
		if c.IsVirtual == nil || *c.IsVirtual != tc.virtual || c.Hypervisor != tc.hv || c.FormFactor != tc.form ||
			c.CloudProvider != tc.cloud || c.CloudInstanceID != tc.instance {
			t.Errorf("%s: %+v (virtual %v)", tc.name, c, c.IsVirtual != nil && *c.IsVirtual)
		}
		if role, _ := LinuxRole(c, false); role != tc.role {
			t.Errorf("%s: linux role %s, want %s", tc.name, role, tc.role)
		}
	}
	if c := dmi(t, "kvm", ""); c.CloudInstanceID != "" || c.Hypervisor != "kvm" {
		t.Errorf("kvm without cpuid: %+v", c)
	}
}

func TestClassifyCPUIDOnly(t *testing.T) {
	c := &model.Classification{}
	classifyFirmware(FirmwareFacts{CPUIDVendor: "XenVMMXenVMM"}, c)
	if !*c.IsVirtual || c.Hypervisor != "xen" {
		t.Errorf("%+v", c)
	}
	c = &model.Classification{}
	classifyFirmware(FirmwareFacts{CPUIDVendor: "unknown"}, c)
	if !*c.IsVirtual || c.Hypervisor != "other" {
		t.Errorf("%+v", c)
	}
}

func TestChassisFormFactor(t *testing.T) {
	for typ, want := range map[int]string{0: "", 2: "", 1: "other", 3: "desktop", 7: "desktop", 9: "laptop", 10: "laptop",
		31: "laptop", 30: "tablet", 17: "server", 23: "server", 28: "server", 12: "other"} {
		if got := ChassisFormFactor(typ); got != want {
			t.Errorf("chassis %d: %q want %q", typ, got, want)
		}
	}
}

func TestLinuxRoleGraphical(t *testing.T) {
	virtual := true
	c := &model.Classification{IsVirtual: &virtual, FormFactor: "other"}
	if r, src := LinuxRole(c, true); r != "workstation" || src != "graphical_target" {
		t.Error(r, src)
	}
	if r, _ := LinuxRole(c, false); r != "server" {
		t.Error(r)
	}
	// A VM's chassis type never makes it a workstation.
	c.FormFactor = "desktop"
	if r, _ := LinuxRole(c, false); r != "server" {
		t.Error(r)
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "etc", "systemd", "system", "default.target")
	if err := os.Symlink("/lib/systemd/system/graphical.target", link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if !GraphicalDefaultTarget(root) {
		t.Error("graphical target not detected")
	}
	_ = os.Remove(link)
	_ = os.Symlink("/lib/systemd/system/multi-user.target", link)
	if GraphicalDefaultTarget(root) || GraphicalDefaultTarget(t.TempDir()) {
		t.Error("multi-user target reported graphical")
	}
}

func TestWindowsRole(t *testing.T) {
	for in, want := range map[string]string{"WinNT": "workstation", "ServerNT": "server", "LanmanNT": "domain_controller", "": ""} {
		if got := WindowsRole(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestMacClassification(t *testing.T) {
	if c := MacClassification("Mac14,2", true, false); c.FormFactor != "laptop" || *c.IsVirtual || c.Role != "workstation" {
		t.Errorf("%+v", c)
	}
	if c := MacClassification("Mac14,13", false, false); c.FormFactor != "desktop" {
		t.Errorf("%+v", c)
	}
	if c := MacClassification("MacBookPro18,3", false, false); c.FormFactor != "laptop" {
		t.Errorf("%+v", c)
	}
	if c := MacClassification("VirtualMac2,1", false, true); !*c.IsVirtual || c.Hypervisor != "apple" || c.FormFactor != "other" {
		t.Errorf("%+v", c)
	}
	if c := MacClassification("Parallels-ARM", false, true); c.Hypervisor != "parallels" {
		t.Errorf("%+v", c)
	}
}

// smbiosStruct builds one SMBIOS structure: formatted area plus strings.
func smbiosStruct(typ byte, formatted []byte, strs ...string) []byte {
	b := append([]byte{typ, byte(4 + len(formatted)), 0x00, 0x01}, formatted...)
	if len(strs) == 0 {
		return append(b, 0, 0)
	}
	for _, s := range strs {
		b = append(append(b, s...), 0)
	}
	return append(b, 0)
}

func TestParseSMBIOS(t *testing.T) {
	uuid := []byte{0x38, 0x0f, 0x6c, 0x9b, 0x2e, 0x5f, 0x51, 0x4a, 0xb8, 0xf0, 0x2e, 0x4c, 0x1d, 0x3a, 0x7b, 0x10}
	t1 := append([]byte{1, 2, 3, 0}, uuid...)  // manufacturer, product, version, serial, UUID
	t1 = append(t1, 6, 0, 0)                   // wake-up type, SKU, family
	t2 := []byte{1, 2, 0, 0, 3, 0}             // manufacturer, product, version, serial, asset tag(4)
	t3 := []byte{1, 0x83, 0, 0, 2, 3, 3, 3, 2} // manufacturer, type 3 + lock bit, version, serial, asset tag
	tbl := smbiosStruct(0, []byte{1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "Microsoft Corporation", "Hyper-V UEFI Release v4.1")
	tbl = append(tbl, smbiosStruct(1, t1, "Microsoft Corporation", "Virtual Machine", "7.0")...)
	tbl = append(tbl, smbiosStruct(2, t2, "Microsoft Corporation", "Virtual Machine", "None")...)
	tbl = append(tbl, smbiosStruct(3, t3, "Microsoft Corporation", azureAssetTag)...)
	tbl = append(tbl, smbiosStruct(127, nil)...)
	raw := []byte{0, 3, 1, 0, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(tbl)))
	raw = append(raw, tbl...)

	f, err := ParseSMBIOS(raw)
	if err != nil {
		t.Fatal(err)
	}
	if f.BIOSVendor != "Microsoft Corporation" || f.SysVendor != "Microsoft Corporation" || f.ProductName != "Virtual Machine" ||
		f.ChassisType != 3 || f.ChassisAssetTag != azureAssetTag || f.BoardAssetTag != "None" ||
		f.ProductUUID != "9b6c0f38-5f2e-4a51-b8f0-2e4c1d3a7b10" {
		t.Fatalf("%+v", f)
	}
	c := &model.Classification{Role: WindowsRole("ServerNT")}
	classifyFirmware(f, c)
	if !*c.IsVirtual || c.Hypervisor != "hyper-v" || c.CloudProvider != "azure" || c.CloudInstanceID != f.ProductUUID {
		t.Errorf("%+v", c)
	}
	// Truncated / garbage tables never panic.
	for i := 0; i < len(raw); i++ {
		_, _ = ParseSMBIOS(raw[:i])
	}
	if _, err := ParseSMBIOS([]byte{1, 2}); err == nil {
		t.Error("short header accepted")
	}
}

func TestSMBIOSUUIDPlaceholders(t *testing.T) {
	if smbiosUUID(make([]byte, 16), 3, 0) != "" || NormalizeUUID("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") != "" {
		t.Error("placeholder uuid kept")
	}
	pre26 := smbiosUUID([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 2, 4)
	if pre26 != "01020304-0506-0708-090a-0b0c0d0e0f10" {
		t.Error(pre26)
	}
}
