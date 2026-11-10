//go:build !windows

package netscan

import (
	"context"
	"net/netip"
	"time"
)

// ICMP echo and ARP are implemented through iphlpapi on Windows only (no raw
// sockets elsewhere): other platforms skip them and rely on TCP and SNMP.

func icmpAvailable() bool { return false }
func arpAvailable() bool  { return false }

func defaultPing() func(context.Context, netip.Addr, time.Duration) (bool, error) { return nil }
func defaultARP() func(context.Context, netip.Addr) (string, bool)                { return nil }
