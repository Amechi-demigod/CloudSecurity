package collector

import (
	"regexp"
	"strings"
)

// gmsaRe is the accepted form of a group Managed Service Account (mirrors the
// server's collector_installer.GMSA_RE): NETBIOS-or-DNS-DOMAIN\name$.
var gmsaRe = regexp.MustCompile(`^[A-Za-z0-9.-]{1,64}\\[A-Za-z0-9._-]{1,63}\$$`)

// ValidGMSA reports whether s looks like DOMAIN\name$.
func ValidGMSA(s string) bool { return gmsaRe.MatchString(s) }

// ClassifyIdentity turns the service's account into what the console shows:
// LocalSystem (S-1-5-18) acts on the network as the computer account
// DOMAIN\HOST$; an account ending in "$" is a (group) managed service account;
// anything else is a regular user account.
func ClassifyIdentity(account, sid, netbiosDomain, hostname string) (runAs, kind string) {
	if sid == "S-1-5-18" || strings.EqualFold(account, `NT AUTHORITY\SYSTEM`) || strings.EqualFold(account, "SYSTEM") {
		host := strings.ToUpper(strings.SplitN(hostname, ".", 2)[0])
		if netbiosDomain == "" || host == "" {
			return `NT AUTHORITY\SYSTEM`, "computer_account"
		}
		return strings.ToUpper(netbiosDomain) + `\` + host + "$", "computer_account"
	}
	if account == "" {
		return "", "unknown"
	}
	if strings.HasSuffix(account, "$") {
		return account, "gmsa"
	}
	return account, "user"
}
