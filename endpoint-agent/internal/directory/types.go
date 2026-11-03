package directory

import (
	"context"
	"strings"
	"time"
)

// Fixed LDAP filters and attribute lists (never taken from the server).
const (
	ComputerFilter = "(objectCategory=computer)"
	UserFilter     = "(&(objectCategory=person)(objectClass=user))"
)

// ComputerAttributes are read for computer objects.
var ComputerAttributes = []string{"objectGUID", "objectSid", "cn", "dNSHostName", "sAMAccountName", "operatingSystem",
	"operatingSystemVersion", "distinguishedName", "userAccountControl", "lastLogonTimestamp", "whenCreated",
	"whenChanged"}

// UserAttributes are read for user objects. memberOf (privileged-group
// detection) is deliberately not collected yet.
var UserAttributes = []string{"objectGUID", "objectSid", "sAMAccountName", "userPrincipalName", "mail", "displayName",
	"givenName", "sn", "department", "title", "manager", "distinguishedName", "userAccountControl",
	"lastLogonTimestamp", "whenCreated", "pwdLastSet"}

// Entry is one search result: attribute names lower-cased, raw values.
type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

func (e Entry) first(name string) []byte {
	v := e.Attrs[strings.ToLower(name)]
	if len(v) == 0 {
		return nil
	}
	return v[0]
}

func (e Entry) str(name string, n int) string { return clean(string(e.first(name)), n) }

// Searcher is a connected, bound directory (the go-ldap backend, or a fake in tests).
type Searcher interface {
	// Search runs a paged subtree search and calls fn for every entry, one
	// page at a time (memory-bounded). An error from fn stops the search.
	Search(ctx context.Context, baseDN, filter string, attrs []string, pageSize int, fn func(Entry) error) error
	// Server is the domain controller in use (for the run record).
	Server() string
	Close() error
}

// Connector connects and binds to the directory described by p.
type Connector func(ctx context.Context, p *Params) (Searcher, error)

// Computer is one computer object as uploaded (CONTRACT: snake_case keys).
type Computer struct {
	ObjectGUID             string     `json:"object_guid"`
	ObjectSID              string     `json:"object_sid"`
	CN                     string     `json:"cn"`
	DNSHostname            string     `json:"dns_hostname"`
	SAMAccountName         string     `json:"sam_account_name"`
	OperatingSystem        string     `json:"operating_system"`
	OperatingSystemVersion string     `json:"operating_system_version"`
	DistinguishedName      string     `json:"distinguished_name"`
	UserAccountControl     int64      `json:"user_account_control"`
	LastLogonTimestamp     *time.Time `json:"last_logon_timestamp"`
	WhenCreated            *time.Time `json:"when_created"`
	WhenChanged            *time.Time `json:"when_changed"`
}

// User is one user object as uploaded.
type User struct {
	ObjectGUID         string     `json:"object_guid"`
	ObjectSID          string     `json:"object_sid"`
	SAMAccountName     string     `json:"sam_account_name"`
	UserPrincipalName  string     `json:"user_principal_name"`
	Mail               string     `json:"mail"`
	DisplayName        string     `json:"display_name"`
	GivenName          string     `json:"given_name"`
	SN                 string     `json:"sn"`
	Department         string     `json:"department"`
	Title              string     `json:"title"`
	ManagerDN          string     `json:"manager_dn"`
	DistinguishedName  string     `json:"distinguished_name"`
	UserAccountControl int64      `json:"user_account_control"`
	LastLogonTimestamp *time.Time `json:"last_logon_timestamp"`
	WhenCreated        *time.Time `json:"when_created"`
	PwdLastSet         *time.Time `json:"pwd_last_set"`
}

const (
	dnLen  = 2048
	strLen = 256
)

func dnOf(e Entry) string {
	if dn := e.str("distinguishedName", dnLen); dn != "" {
		return dn
	}
	return clean(e.DN, dnLen)
}

// ComputerFromEntry converts an entry; ok is false when it has no usable objectGUID.
func ComputerFromEntry(e Entry) (Computer, bool) {
	g := GUIDString(e.first("objectGUID"))
	if g == "" {
		return Computer{}, false
	}
	return Computer{
		ObjectGUID:             g,
		ObjectSID:              SIDString(e.first("objectSid")),
		CN:                     e.str("cn", strLen),
		DNSHostname:            strings.ToLower(e.str("dNSHostName", strLen)),
		SAMAccountName:         e.str("sAMAccountName", strLen),
		OperatingSystem:        e.str("operatingSystem", strLen),
		OperatingSystemVersion: e.str("operatingSystemVersion", strLen),
		DistinguishedName:      dnOf(e),
		UserAccountControl:     Int(string(e.first("userAccountControl"))),
		LastLogonTimestamp:     FileTime(string(e.first("lastLogonTimestamp"))),
		WhenCreated:            GeneralizedTime(string(e.first("whenCreated"))),
		WhenChanged:            GeneralizedTime(string(e.first("whenChanged"))),
	}, true
}

// UserFromEntry converts an entry; ok is false when it has no usable objectGUID.
func UserFromEntry(e Entry) (User, bool) {
	g := GUIDString(e.first("objectGUID"))
	if g == "" {
		return User{}, false
	}
	return User{
		ObjectGUID:         g,
		ObjectSID:          SIDString(e.first("objectSid")),
		SAMAccountName:     e.str("sAMAccountName", strLen),
		UserPrincipalName:  e.str("userPrincipalName", strLen),
		Mail:               e.str("mail", strLen),
		DisplayName:        e.str("displayName", strLen),
		GivenName:          e.str("givenName", strLen),
		SN:                 e.str("sn", strLen),
		Department:         e.str("department", strLen),
		Title:              e.str("title", strLen),
		ManagerDN:          e.str("manager", dnLen),
		DistinguishedName:  dnOf(e),
		UserAccountControl: Int(string(e.first("userAccountControl"))),
		LastLogonTimestamp: FileTime(string(e.first("lastLogonTimestamp"))),
		WhenCreated:        GeneralizedTime(string(e.first("whenCreated"))),
		PwdLastSet:         FileTime(string(e.first("pwdLastSet"))),
	}, true
}

// Totals counts uploaded objects.
type Totals struct {
	Computers int `json:"computers"`
	Users     int `json:"users"`
}

// Batch is one upload (CONTRACT section 4). Final-only fields are omitted otherwise.
type Batch struct {
	Seq        int        `json:"seq"`
	Final      bool       `json:"final"`
	Computers  []Computer `json:"computers"`
	Users      []User     `json:"users"`
	Status     string     `json:"status,omitempty"`
	Error      string     `json:"error,omitempty"`
	Truncated  bool       `json:"truncated"`
	Totals     *Totals    `json:"totals,omitempty"`
	DurationMS int64      `json:"duration_ms,omitempty"`
	Server     string     `json:"server,omitempty"`
}
