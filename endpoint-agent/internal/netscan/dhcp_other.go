//go:build !windows

package netscan

import "context"

// The DHCP Server Management API exists on Windows only.
const subnetsSupported = false

type noDHCP struct{}

func (noDHCP) Scopes(context.Context, string) ([]DHCPScope, error) { return nil, ErrUnsupported }

func defaultDHCP() DHCPClient { return noDHCP{} }

func dhcpAvailable() bool { return false }
