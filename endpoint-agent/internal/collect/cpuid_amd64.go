package collect

import "encoding/binary"

func cpuid(eaxArg, ecxArg uint32) (eax, ebx, ecx, edx uint32)

// cpuidHypervisor returns the hypervisor vendor signature (CPUID leaf
// 0x40000000) when the hypervisor-present bit (leaf 1, ECX bit 31) is set.
func cpuidHypervisor() string {
	if _, _, ecx, _ := cpuid(1, 0); ecx&(1<<31) == 0 {
		return ""
	}
	_, b, c, d := cpuid(0x40000000, 0)
	sig := make([]byte, 12)
	binary.LittleEndian.PutUint32(sig[0:], b)
	binary.LittleEndian.PutUint32(sig[4:], c)
	binary.LittleEndian.PutUint32(sig[8:], d)
	if s := string(sig); s != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" {
		return s
	}
	return "unknown"
}
