package directory

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Attribute decoding for Active Directory values.

// GUIDString decodes a 16-byte objectGUID: the first three groups are
// little-endian (Microsoft GUID layout), giving the same text as
// [guid]::new(bytes) / Get-ADComputer's ObjectGUID, lower-cased.
func GUIDString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]), binary.LittleEndian.Uint16(b[6:8]), b[8:10], b[10:16])
}

// SIDString decodes a binary SID (objectSid) to S-1-5-21-... form.
func SIDString(b []byte) string {
	if len(b) < 8 || b[0] != 1 {
		return ""
	}
	n := int(b[1])
	if n > 15 || len(b) != 8+4*n {
		return ""
	}
	var auth uint64
	for _, x := range b[2:8] {
		auth = auth<<8 | uint64(x)
	}
	var sb strings.Builder
	sb.WriteString("S-1-")
	sb.WriteString(strconv.FormatUint(auth, 10))
	for i := 0; i < n; i++ {
		sb.WriteByte('-')
		sb.WriteString(strconv.FormatUint(uint64(binary.LittleEndian.Uint32(b[8+4*i:])), 10))
	}
	return sb.String()
}

// fileTimeEpochDiff is the number of 100 ns intervals between 1601-01-01 and 1970-01-01.
const fileTimeEpochDiff = 116444736000000000

// FileTime decodes a FILETIME integer attribute (lastLogonTimestamp,
// pwdLastSet, accountExpires). 0 ("never") and 0x7FFFFFFFFFFFFFFF ("not set")
// give nil.
func FileTime(s string) *time.Time {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || v <= 0 || v == 0x7FFFFFFFFFFFFFFF || v < fileTimeEpochDiff {
		return nil
	}
	t := time.Unix(0, 0).UTC().Add(time.Duration((v-fileTimeEpochDiff)/10_000_000) * time.Second)
	if t.Year() > 9999 {
		return nil
	}
	return &t
}

// GeneralizedTime decodes an LDAP GeneralizedTime (whenCreated: 20260101123456.0Z).
func GeneralizedTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"20060102150405.0Z", "20060102150405Z", "20060102150405.0Z0700", "20060102150405Z0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// Int parses an integer attribute (userAccountControl); 0 when absent/invalid.
func Int(s string) int64 {
	v, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// userAccountControl flags.
const (
	UACAccountDisable = 0x0002
)

// Disabled reports the ACCOUNTDISABLE flag.
func Disabled(uac int64) bool { return uac&UACAccountDisable != 0 }

// clean returns a valid UTF-8 string without control characters, at most n bytes.
func clean(s string, n int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
