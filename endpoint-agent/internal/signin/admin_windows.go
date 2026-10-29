//go:build windows

package signin

import (
	"context"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
)

// winAdminProbe answers EnabledLocalAdmins via collect.EnabledLocalAdminNames
// (raw Win32 NetLocalGroupGetMembers/NetUserGetInfo - not PowerShell
// Get-LocalGroupMember, which throws on Entra-joined devices with Azure AD
// members in Administrators).
type winAdminProbe struct{}

func (winAdminProbe) EnabledLocalAdmins(ctx context.Context) ([]string, error) {
	return collect.EnabledLocalAdminNames(ctx)
}
