//go:build windows

package directory

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wldap32.dll through syscalls (no cgo): the least fragile way to get a
// Kerberos-sealed LDAP session from Go. The library negotiates the SASL
// security layer itself (SSPI Negotiate with sign + seal); this file only
// passes handles, options and buffers. Memory returned by the library is
// freed with the library's own functions and never kept.

const sealedSupported = true

var (
	wldap32                  = windows.NewLazySystemDLL("wldap32.dll")
	procLdapInit             = wldap32.NewProc("ldap_initW")
	procLdapSetOption        = wldap32.NewProc("ldap_set_optionW")
	procLdapGetOption        = wldap32.NewProc("ldap_get_optionW")
	procLdapConnect          = wldap32.NewProc("ldap_connect")
	procLdapBindS            = wldap32.NewProc("ldap_bind_sW")
	procLdapSearchInitPage   = wldap32.NewProc("ldap_search_init_pageW")
	procLdapGetNextPageS     = wldap32.NewProc("ldap_get_next_page_s")
	procLdapSearchAbandon    = wldap32.NewProc("ldap_search_abandon_page")
	procLdapFirstEntry       = wldap32.NewProc("ldap_first_entry")
	procLdapNextEntry        = wldap32.NewProc("ldap_next_entry")
	procLdapGetDN            = wldap32.NewProc("ldap_get_dnW")
	procLdapMemFree          = wldap32.NewProc("ldap_memfreeW")
	procLdapGetValuesLen     = wldap32.NewProc("ldap_get_values_lenW")
	procLdapValueFreeLen     = wldap32.NewProc("ldap_value_free_len")
	procLdapMsgFree          = wldap32.NewProc("ldap_msgfree")
	procLdapUnbind           = wldap32.NewProc("ldap_unbind")
	procLdapGetLastError     = wldap32.NewProc("LdapGetLastError")
	ldapAuthNegotiate        = uintptr(0x0486)
	ldapScopeSubtree         = uintptr(2)
	errLdapLibraryNotPresent = fmt.Errorf("wldap32.dll is not available")
)

func init() { sealedAPI = &winLDAP{attrs: map[uintptr][]string{}} }

type lTimeval struct{ Sec, Usec int32 }

type berval struct {
	Len uint32
	Val *byte
}

// ptr converts a pointer returned by the library (as uintptr) without
// tripping go vet; the memory belongs to wldap32, not to the Go heap.
func ptr(u uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&u)) }

type winLDAP struct {
	mu    sync.Mutex
	attrs map[uintptr][]string // attributes requested per search handle
}

func lastError(op string) error {
	code, _, _ := procLdapGetLastError.Call()
	return &LDAPError{Op: op, Code: uint32(code)}
}

func ldapResult(op string, rc uintptr) error {
	if rc == ldapSuccess {
		return nil
	}
	return &LDAPError{Op: op, Code: uint32(rc)}
}

func (w *winLDAP) Init(host string, port int) (uintptr, error) {
	if err := procLdapInit.Find(); err != nil {
		return 0, errLdapLibraryNotPresent
	}
	h16, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return 0, err
	}
	ld, _, _ := procLdapInit.Call(uintptr(unsafe.Pointer(h16)), uintptr(port))
	if ld == 0 {
		return 0, lastError("ldap_init")
	}
	return ld, nil
}

func (w *winLDAP) SetOption(h uintptr, opt int, val uint32) error {
	v := val
	rc, _, _ := procLdapSetOption.Call(h, uintptr(opt), uintptr(unsafe.Pointer(&v)))
	return ldapResult("ldap_set_option", rc)
}

func (w *winLDAP) GetOption(h uintptr, opt int) (uint32, error) {
	var v uint32
	rc, _, _ := procLdapGetOption.Call(h, uintptr(opt), uintptr(unsafe.Pointer(&v)))
	return v, ldapResult("ldap_get_option", rc)
}

func timeval(d time.Duration) *lTimeval {
	return &lTimeval{Sec: int32(d / time.Second)}
}

func (w *winLDAP) Connect(h uintptr, timeout time.Duration) error {
	tv := timeval(timeout)
	rc, _, _ := procLdapConnect.Call(h, uintptr(unsafe.Pointer(tv)))
	return ldapResult("connect", rc)
}

func (w *winLDAP) BindNegotiate(h uintptr) error {
	// dn and credentials NULL: the process's own identity (computer account /
	// gMSA) through SSPI Negotiate; signing and sealing were requested above.
	rc, _, _ := procLdapBindS.Call(h, 0, 0, ldapAuthNegotiate)
	return ldapResult("Kerberos (Negotiate) bind", rc)
}

func (w *winLDAP) SearchInit(h uintptr, baseDN, filter string, attrs []string, timeLimit time.Duration) (uintptr, error) {
	base16, err := windows.UTF16PtrFromString(baseDN)
	if err != nil {
		return 0, err
	}
	filter16, err := windows.UTF16PtrFromString(filter)
	if err != nil {
		return 0, err
	}
	list := make([]*uint16, 0, len(attrs)+1)
	for _, a := range attrs {
		a16, err := windows.UTF16PtrFromString(a)
		if err != nil {
			return 0, err
		}
		list = append(list, a16)
	}
	list = append(list, nil)
	s, _, _ := procLdapSearchInitPage.Call(h, uintptr(unsafe.Pointer(base16)), ldapScopeSubtree,
		uintptr(unsafe.Pointer(filter16)), uintptr(unsafe.Pointer(&list[0])), 0, 0, 0,
		uintptr(timeLimit/time.Second), 0, 0)
	if s == 0 {
		return 0, lastError("search")
	}
	w.mu.Lock()
	w.attrs[s] = append([]string(nil), attrs...)
	w.mu.Unlock()
	return s, nil
}

func (w *winLDAP) NextPage(h, search uintptr, timeout time.Duration, pageSize int) ([]Entry, bool, error) {
	var total uint32
	var msg uintptr
	tv := timeval(timeout)
	rc, _, _ := procLdapGetNextPageS.Call(h, search, uintptr(unsafe.Pointer(tv)), uintptr(pageSize),
		uintptr(unsafe.Pointer(&total)), uintptr(unsafe.Pointer(&msg)))
	if msg != 0 {
		defer procLdapMsgFree.Call(msg) //nolint:errcheck
	}
	if rc == ldapNoResultsReturned {
		return nil, true, nil
	}
	if rc != ldapSuccess {
		return nil, false, &LDAPError{Op: "search", Code: uint32(rc)}
	}
	w.mu.Lock()
	attrs := w.attrs[search]
	w.mu.Unlock()
	var out []Entry
	for e, _, _ := procLdapFirstEntry.Call(h, msg); e != 0; e, _, _ = procLdapNextEntry.Call(h, e) {
		en := Entry{Attrs: map[string][][]byte{}}
		if dn, _, _ := procLdapGetDN.Call(h, e); dn != 0 {
			en.DN = windows.UTF16PtrToString((*uint16)(ptr(dn)))
			procLdapMemFree.Call(dn) //nolint:errcheck
		}
		for _, a := range attrs {
			a16, err := windows.UTF16PtrFromString(a)
			if err != nil {
				continue
			}
			vals, _, _ := procLdapGetValuesLen.Call(h, e, uintptr(unsafe.Pointer(a16)))
			if vals == 0 {
				continue
			}
			var vs [][]byte
			for i := uintptr(0); ; i++ {
				bv := *(**berval)(unsafe.Add(ptr(vals), i*unsafe.Sizeof(uintptr(0))))
				if bv == nil {
					break
				}
				var b []byte
				if bv.Len > 0 && bv.Val != nil {
					b = append([]byte(nil), unsafe.Slice(bv.Val, bv.Len)...)
				}
				vs = append(vs, b)
			}
			procLdapValueFreeLen.Call(vals) //nolint:errcheck
			en.Attrs[lower(a)] = vs
		}
		out = append(out, en)
	}
	return out, false, nil
}

func (w *winLDAP) SearchAbandon(h, search uintptr) {
	procLdapSearchAbandon.Call(h, search) //nolint:errcheck
	w.mu.Lock()
	delete(w.attrs, search)
	w.mu.Unlock()
}

func (w *winLDAP) Unbind(h uintptr) { procLdapUnbind.Call(h) } //nolint:errcheck

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
