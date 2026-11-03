//go:build windows

package collect

import (
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
)

// Domain-join facts on Windows, all read locally (no DC / LDAP traffic except
// the bounded computer-SID lookup):
//   - LsaQueryInformationPolicy(PolicyDnsDomainInformation): NetBIOS domain,
//     DNS domain, forest and domain SID (NULL SID = not AD-joined);
//   - LookupAccountName("NETBIOS\HOST$"): the computer account's SID (may
//     need a DC; 5 s budget, cached for the process lifetime);
//   - GetComputerNameEx(ComputerNameDnsFullyQualified);
//   - NetGetAadJoinInformation: Entra (Azure AD) device id, tenant id, join type;
//   - HKLM\SOFTWARE\Microsoft\Enrollments: the Intune (MDM) enrollment id.

// LSA procs, lsaUnicodeString and lsaOpenPolicyLocal live in admins_windows.go.
var (
	procNetGetAadJoinInformation  = netapi32.NewProc("NetGetAadJoinInformation")
	procNetFreeAadJoinInformation = netapi32.NewProc("NetFreeAadJoinInformation")
)

const policyDNSDomainInformation = 12

// policyDNSDomainInfo mirrors POLICY_DNS_DOMAIN_INFO.
type policyDNSDomainInfo struct {
	Name          lsaUnicodeString
	DNSDomainName lsaUnicodeString
	DNSForestName lsaUnicodeString
	DomainGUID    windows.GUID
	Sid           *windows.SID
}

// dsregJoinInfo mirrors the leading fields of DSREG_JOIN_INFO (lmjoin.h):
//
//	DSREG_JOIN_TYPE joinType; PCCERT_CONTEXT pJoinCertificate; LPWSTR pszDeviceId;
//	LPWSTR pszIdpDomain; LPWSTR pszTenantId; ...
//
// Only read through the pointer the API returns, so declaring a prefix is
// safe; Go's alignment pads JoinType to pointer size exactly like C does.
type dsregJoinInfo struct {
	JoinType        uint32
	JoinCertificate uintptr
	DeviceID        *uint16
	IdpDomain       *uint16
	TenantID        *uint16
}

func lsaString(u lsaUnicodeString) string {
	if u.Buffer == nil || u.Length == 0 {
		return ""
	}
	return windows.UTF16ToString(unsafe.Slice(u.Buffer, int(u.Length/2)))
}

func lsaDNSDomainInfo() (netbios, dns, forest, domainSID string, err error) {
	h, err := lsaOpenPolicyLocal(policyViewLocalInformation)
	if err != nil {
		return "", "", "", "", err
	}
	defer func() { _, _, _ = procLsaClose.Call(uintptr(h)) }()
	var buf *policyDNSDomainInfo
	r, _, _ := procLsaQueryInformationPolicy.Call(uintptr(h), policyDNSDomainInformation, uintptr(unsafe.Pointer(&buf)))
	if err := lsaCheck(r); err != nil {
		return "", "", "", "", err
	}
	if buf == nil {
		return "", "", "", "", nil
	}
	defer func() { _, _, _ = procLsaFreeMemory.Call(uintptr(unsafe.Pointer(buf))) }()
	if buf.Sid == nil {
		return "", "", "", "", nil // workgroup: Name is the workgroup, not a domain
	}
	return lsaString(buf.Name), lsaString(buf.DNSDomainName), lsaString(buf.DNSForestName), buf.Sid.String(), nil
}

func computerName(kind uint32) string {
	n := uint32(256)
	b := make([]uint16, n)
	if err := windows.GetComputerNameEx(kind, &b[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(b[:n])
}

var (
	sidCacheMu  sync.Mutex
	sidCache    = map[string]string{}
	sidInFlight atomic.Bool
)

// computerAccountSID looks up "NETBIOS\HOST$" with a 5 s budget. A lookup
// that is still running from an earlier check-in is not started again.
func computerAccountSID(netbios, host string) string {
	account := netbios + `\` + host + "$"
	sidCacheMu.Lock()
	if v, ok := sidCache[account]; ok {
		sidCacheMu.Unlock()
		return v
	}
	sidCacheMu.Unlock()
	if !sidInFlight.CompareAndSwap(false, true) {
		return ""
	}
	done := make(chan string, 1)
	go func() {
		defer sidInFlight.Store(false)
		sid, _, _, err := windows.LookupSID("", account)
		if err != nil || sid == nil {
			done <- ""
			return
		}
		s := sid.String()
		sidCacheMu.Lock()
		sidCache[account] = s
		sidCacheMu.Unlock()
		done <- s
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(5 * time.Second):
		return ""
	}
}

func aadJoin(j *model.DirectoryJoin) {
	if procNetGetAadJoinInformation.Find() != nil || procNetFreeAadJoinInformation.Find() != nil {
		return // older than Windows 10
	}
	var info *dsregJoinInfo
	if r, _, _ := procNetGetAadJoinInformation.Call(0, uintptr(unsafe.Pointer(&info))); r != 0 || info == nil {
		return
	}
	defer func() { _, _, _ = procNetFreeAadJoinInformation.Call(uintptr(unsafe.Pointer(info))) }()
	switch info.JoinType {
	case 1:
		j.EntraJoinType = "joined"
	case 2:
		j.EntraJoinType = "registered"
	default:
		return
	}
	if info.DeviceID != nil {
		j.EntraDeviceID = windows.UTF16PtrToString(info.DeviceID)
	}
	if info.TenantID != nil {
		j.EntraTenantID = windows.UTF16PtrToString(info.TenantID)
	}
}

func intuneEnrollmentID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Enrollments`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(256)
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		pid, _, _ := sk.GetStringValue("ProviderID")
		sk.Close()
		if pid == "MS DM Server" {
			return n
		}
	}
	return ""
}

// windowsJoin gathers the join facts; it never fails (nil when not joined).
func windowsJoin() (j *model.DirectoryJoin) {
	defer func() {
		if p := recover(); p != nil {
			slog.Warn("directory join facts unavailable", "panic", p)
			j = nil
		}
	}()
	j = &model.DirectoryJoin{}
	netbios, dns, forest, domainSID, err := lsaDNSDomainInfo()
	if err != nil {
		slog.Debug("LSA domain information unavailable", "err", err)
	}
	if domainSID != "" {
		j.ADNetbios, j.ADDomain, j.ADForest, j.ADDomainSID, j.Source = netbios, dns, forest, domainSID, "lsa"
		if host := computerName(windows.ComputerNameNetBIOS); host != "" && netbios != "" {
			j.ADComputerSID = computerAccountSID(netbios, host)
			if !strings.HasPrefix(j.ADComputerSID, domainSID+"-") {
				j.ADComputerSID = "" // not this domain's computer account
			}
		}
		j.DNSHostname = computerName(windows.ComputerNameDnsFullyQualified)
	}
	aadJoin(j)
	j.IntuneEnrollmentID = intuneEnrollmentID()
	return j // model.Normalize drops it when empty
}
