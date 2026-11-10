//go:build windows

package netscan

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ICMP echo and ARP through the IP Helper API (iphlpapi.dll): no raw
// sockets, no pcap, no driver. IcmpSendEcho2 / SendARP need no elevation.

var (
	iphlpapi            = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2   = iphlpapi.NewProc("IcmpSendEcho2")
	procSendARP         = iphlpapi.NewProc("SendARP")
)

const (
	ipSuccess   = 0
	icmpPayload = "cnapp-discovery"
)

// Compile-time checks that the implementations keep the Env hook shapes.
var (
	_ func(context.Context, netip.Addr, time.Duration) (bool, error) = icmpPing
	_ func(context.Context, netip.Addr) (string, bool)               = sendARP
)

func icmpAvailable() bool { return procIcmpSendEcho2.Find() == nil && procIcmpCreateFile.Find() == nil }
func arpAvailable() bool  { return procSendARP.Find() == nil }

// ipaddr converts to the IPAddr of the IP Helper API: network byte order in memory.
func ipaddr(a netip.Addr) uint32 { b := a.As4(); return binary.LittleEndian.Uint32(b[:]) }

// icmpPing sends one ICMP echo request (synchronous IcmpSendEcho2) and
// reports whether an echo reply came back within timeout.
func icmpPing(ctx context.Context, ip netip.Addr, timeout time.Duration) (bool, error) {
	if !icmpAvailable() {
		return false, errors.New("iphlpapi ICMP functions are not available")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	h, _, callErr := procIcmpCreateFile.Call()
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return false, callErr
	}
	defer procIcmpCloseHandle.Call(h)
	data := []byte(icmpPayload)
	// ICMP_ECHO_REPLY (up to 40 bytes) + payload + 8 (ICMP error) + IO_STATUS_BLOCK (16).
	reply := make([]byte, 40+len(data)+8+16)
	r, _, _ := procIcmpSendEcho2.Call(h, 0, 0, 0, uintptr(ipaddr(ip)), uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if r == 0 {
		return false, nil // timeout / unreachable: not alive (never an error for the scan)
	}
	// ICMP_ECHO_REPLY starts with Address (4 bytes) and Status (4 bytes).
	return binary.LittleEndian.Uint32(reply[4:8]) == ipSuccess &&
		binary.LittleEndian.Uint32(reply[0:4]) == ipaddr(ip), nil
}

// sendARP resolves an on-link address to its MAC with one ARP request.
func sendARP(ctx context.Context, ip netip.Addr) (string, bool) {
	if !arpAvailable() || ctx.Err() != nil {
		return "", false
	}
	var mac [2]uint32 // ULONG[2]: 8 bytes, 6 used
	n := uint32(8)
	r, _, _ := procSendARP.Call(uintptr(ipaddr(ip)), 0, uintptr(unsafe.Pointer(&mac[0])), uintptr(unsafe.Pointer(&n)))
	if r != 0 || n < 6 {
		return "", false
	}
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:], mac[0])
	binary.LittleEndian.PutUint32(b[4:], mac[1])
	m := macString(b[:6])
	if m == "00:00:00:00:00:00" || m == "ff:ff:ff:ff:ff:ff" {
		return "", false
	}
	return m, true
}

func defaultPing() func(context.Context, netip.Addr, time.Duration) (bool, error) { return icmpPing }
func defaultARP() func(context.Context, netip.Addr) (string, bool)                { return sendARP }
