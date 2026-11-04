//go:build !amd64

package collect

// cpuidHypervisor: CPUID is x86-only; other architectures rely on SMBIOS / DMI.
func cpuidHypervisor() string { return "" }
