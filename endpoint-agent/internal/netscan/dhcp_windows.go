//go:build windows

package netscan

import (
	"context"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DHCP Server Management API (dhcpsapi.dll, RPC to the DHCP server): enumerate
// the scopes ("subnets") of a server with DhcpEnumSubnets, read each with
// DhcpGetSubnetInfo and its address range with DhcpEnumSubnetElements. Read
// only; no PowerShell. The collector's account needs membership of the
// "DHCP Users" group on the DHCP server. Not exercised in CI (needs a DHCP
// server): see docs/NETWORK_DISCOVERY_COLLECTOR.md.

const subnetsSupported = true

var (
	dhcpsapi                = windows.NewLazySystemDLL("dhcpsapi.dll")
	procDhcpEnumSubnets     = dhcpsapi.NewProc("DhcpEnumSubnets")
	procDhcpGetSubnetInfo   = dhcpsapi.NewProc("DhcpGetSubnetInfo")
	procDhcpEnumSubnetElems = dhcpsapi.NewProc("DhcpEnumSubnetElements")
	procDhcpRpcFreeMemory   = dhcpsapi.NewProc("DhcpRpcFreeMemory")
)

const (
	errMoreData          = 234
	errNoMoreItems       = 259
	errAccessDenied      = 5
	errRPCServerDown     = 1722
	errRPCUnavailable    = 1753
	dhcpIPRanges         = 0 // DHCP_SUBNET_ELEMENT_TYPE DhcpIpRanges
	dhcpPreferredMaximum = 1024
)

type dhcpIPArray struct {
	NumElements uint32
	Elements    *uint32
}

type dhcpSubnetInfo struct {
	Address, Mask uint32
	Name, Comment *uint16
	HostIP        uint32
	NetBIOSName   *uint16
	HostName      *uint16
	State         uint32
}

type dhcpElementArray struct {
	NumElements uint32
	Elements    unsafe.Pointer // *dhcpElementData
}

type dhcpElementData struct {
	Type uint32
	Elem unsafe.Pointer // union: *DHCP_IP_RANGE for DhcpIpRanges
}

type dhcpIPRange struct{ Start, End uint32 }

// Compile-time check: the Windows implementation satisfies DHCPClient.
var _ DHCPClient = winDHCP{}

type winDHCP struct{}

func defaultDHCP() DHCPClient { return winDHCP{} }

func dhcpAvailable() bool {
	return procDhcpEnumSubnets.Find() == nil && procDhcpGetSubnetInfo.Find() == nil
}

func dhcpIP(u uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func dhcpError(server string, code uintptr) error {
	switch code {
	case errAccessDenied:
		return fmt.Errorf("access denied: add the collector's account to the 'DHCP Users' group on %s", server)
	case errRPCServerDown, errRPCUnavailable:
		return fmt.Errorf("the DHCP server is not reachable over RPC (error %d)", code)
	}
	return fmt.Errorf("DHCP API error %s (%d)", windows.Errno(code).Error(), code)
}

func free(p unsafe.Pointer) {
	if p != nil {
		procDhcpRpcFreeMemory.Call(uintptr(p))
	}
}

// Scopes lists the scopes of server.
func (winDHCP) Scopes(ctx context.Context, server string) ([]DHCPScope, error) {
	if err := dhcpsapi.Load(); err != nil {
		return nil, fmt.Errorf("dhcpsapi.dll is not available: %w", err)
	}
	srv, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return nil, err
	}
	var subnets []uint32
	var resume uint32
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var arr *dhcpIPArray
		var read, total uint32
		r, _, _ := procDhcpEnumSubnets.Call(uintptr(unsafe.Pointer(srv)), uintptr(unsafe.Pointer(&resume)),
			dhcpPreferredMaximum, uintptr(unsafe.Pointer(&arr)), uintptr(unsafe.Pointer(&read)),
			uintptr(unsafe.Pointer(&total)))
		if r != 0 && r != errMoreData && r != errNoMoreItems {
			return nil, dhcpError(server, r)
		}
		if arr != nil {
			if arr.Elements != nil {
				subnets = append(subnets, unsafe.Slice(arr.Elements, arr.NumElements)...)
			}
			free(unsafe.Pointer(arr))
		}
		if r != errMoreData || len(subnets) >= maxDHCPScopes {
			break
		}
	}
	var out []DHCPScope
	for _, s := range subnets {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		var info *dhcpSubnetInfo
		r, _, _ := procDhcpGetSubnetInfo.Call(uintptr(unsafe.Pointer(srv)), uintptr(s), uintptr(unsafe.Pointer(&info)))
		if r != 0 || info == nil {
			return out, dhcpError(server, r)
		}
		sc := DHCPScope{Server: server, Scope: dhcpIP(info.Address), Mask: dhcpIP(info.Mask),
			Name: cleanBanner([]byte(windows.UTF16PtrToString(info.Name)), 128)}
		free(unsafe.Pointer(info))
		sc.Start, sc.End = dhcpRange(srv, s)
		out = append(out, sc)
	}
	return out, nil
}

// dhcpRange is the lowest start and highest end of the scope's IP ranges
// (empty strings when they cannot be read).
func dhcpRange(srv *uint16, subnet uint32) (string, string) {
	var lo, hi uint32
	have := false
	var resume uint32
	for {
		var arr *dhcpElementArray
		var read, total uint32
		r, _, _ := procDhcpEnumSubnetElems.Call(uintptr(unsafe.Pointer(srv)), uintptr(subnet), dhcpIPRanges,
			uintptr(unsafe.Pointer(&resume)), dhcpPreferredMaximum, uintptr(unsafe.Pointer(&arr)),
			uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
		if r != 0 && r != errMoreData && r != errNoMoreItems {
			break
		}
		if arr != nil {
			if arr.Elements != nil {
				for _, el := range unsafe.Slice((*dhcpElementData)(arr.Elements), arr.NumElements) {
					if el.Type != dhcpIPRanges || el.Elem == nil {
						continue
					}
					rg := (*dhcpIPRange)(el.Elem)
					if !have || rg.Start < lo {
						lo = rg.Start
					}
					if !have || rg.End > hi {
						hi = rg.End
					}
					have = true
				}
			}
			free(unsafe.Pointer(arr))
		}
		if r != errMoreData {
			break
		}
	}
	if !have {
		return "", ""
	}
	return dhcpIP(lo), dhcpIP(hi)
}
