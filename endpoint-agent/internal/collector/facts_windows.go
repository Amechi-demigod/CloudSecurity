//go:build windows

package collector

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

// HostFacts reads everything locally: host and domain names, the OS, whether
// this host is a domain controller (ProductType LanmanNT) and the identity the
// service runs as.
func HostFacts() Facts {
	f := Facts{Architecture: runtime.GOARCH, Version: version.Version, Features: Features}
	f.Hostname, _ = os.Hostname()
	f.DNSHostname = strings.ToLower(computerName(windows.ComputerNameDnsFullyQualified))
	f.Domain = strings.ToLower(computerName(windows.ComputerNameDnsDomain))
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE); err == nil {
		name, _, _ := k.GetStringValue("ProductName")
		build, _, _ := k.GetStringValue("CurrentBuildNumber")
		k.Close()
		f.OSName, f.OSVersion = name, build
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\ProductOptions`,
		registry.QUERY_VALUE); err == nil {
		pt, _, _ := k.GetStringValue("ProductType")
		k.Close()
		f.IsDomainController = strings.EqualFold(pt, "LanmanNT")
	}
	account, sid := currentAccount()
	f.RunAs, f.RunAsKind = ClassifyIdentity(account, sid, netbios(), f.Hostname)
	return f
}

func computerName(kind uint32) string {
	n := uint32(256)
	buf := make([]uint16, n)
	if err := windows.GetComputerNameEx(kind, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// netbios is the NetBIOS domain name (NetGetJoinInformation), "" when not domain-joined.
func netbios() string {
	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err != nil {
		return ""
	}
	defer windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	if status != windows.NetSetupDomainName {
		return ""
	}
	return windows.UTF16PtrToString(name)
}

// currentAccount is DOMAIN\name and the SID of the process token.
func currentAccount() (string, string) {
	t := windows.GetCurrentProcessToken()
	u, err := t.GetTokenUser()
	if err != nil {
		return "", ""
	}
	sid := u.User.Sid.String()
	acct, dom, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return "", sid
	}
	return fmt.Sprintf(`%s\%s`, dom, acct), sid
}
