//go:build windows

package collect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Classification on Windows without WMI: the OS product type from the
// registry (ProductOptions\ProductType, the value RtlGetVersion reports as
// wProductType), the raw SMBIOS table from GetSystemFirmwareTable('RSMB')
// and the CPUID hypervisor leaf.

var procGetSystemFirmwareTable = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemFirmwareTable")

const rsmbSignature = 'R'<<24 | 'S'<<16 | 'M'<<8 | 'B'

func rawSMBIOS() ([]byte, error) {
	if err := procGetSystemFirmwareTable.Find(); err != nil {
		return nil, err
	}
	n, _, err := procGetSystemFirmwareTable.Call(rsmbSignature, 0, 0, 0)
	if n == 0 {
		return nil, fmt.Errorf("GetSystemFirmwareTable size: %w", err)
	}
	buf := make([]byte, n)
	got, _, err := procGetSystemFirmwareTable.Call(rsmbSignature, 0, uintptr(unsafe.Pointer(&buf[0])), n)
	if got == 0 || got > n {
		return nil, fmt.Errorf("GetSystemFirmwareTable: %w", err)
	}
	return buf[:got], nil
}

func windowsProductType() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ProductOptions`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("ProductType")
	return v
}

func windowsClassification() (*model.Classification, error) {
	c := &model.Classification{Role: WindowsRole(windowsProductType()), RoleSource: "product_type"}
	raw, err := rawSMBIOS()
	var f FirmwareFacts
	if err == nil {
		f, err = ParseSMBIOS(raw)
	}
	f.CPUIDVendor = cpuidHypervisor()
	classifyFirmware(f, c)
	if err != nil && c.Hypervisor == "" {
		c.IsVirtual = nil // no SMBIOS: physical is not proven
	}
	return c, err
}
