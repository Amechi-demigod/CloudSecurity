//go:build !windows

package directory

import (
	"crypto/x509"
	"errors"

	"github.com/go-ldap/ldap/v3"
)

const kerberosSupported = false

// kerberosBind: the computer-account (SSPI) bind is Windows-only; macOS and
// Linux collectors use a read-only service account.
func kerberosBind(*ldap.Conn, string, *x509.Certificate) error {
	return errors.New("computer-account (Kerberos) bind is only supported on Windows collectors")
}
