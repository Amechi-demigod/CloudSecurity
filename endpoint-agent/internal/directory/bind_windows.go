//go:build windows

package directory

import (
	"crypto/x509"
	"errors"
	"net"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
)

const kerberosSupported = true

// kerberosBind binds as the process's identity (the computer account when
// running as LocalSystem) with SASL GSSAPI over SSPI. The bind runs inside
// the TLS session and carries an RFC 5929 tls-server-end-point channel
// binding token, so it also works against DCs that enforce LDAP channel
// binding. No SASL security layer is negotiated: TLS already provides
// integrity and confidentiality (go-ldap does not implement SASL wrapping,
// which is why plain LDAP on 389 is never used).
func kerberosBind(conn *ldap.Conn, host string, leaf *x509.Certificate) error {
	if net.ParseIP(host) != nil {
		return errors.New("Kerberos needs the domain controller's DNS name (ldap/<fqdn> SPN), not an IP address")
	}
	client, err := gssapi.NewSSPIClientWithChannelBinding(leaf)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	return conn.GSSAPIBind(client, "ldap/"+host, "")
}
