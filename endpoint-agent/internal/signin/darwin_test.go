//go:build darwin

package signin

import (
	"strings"
	"testing"
)

// TestParseDSCLAttrNestedGroups uses a fake dscl -read output (no real OS
// calls) to confirm a NestedGroups line is parsed correctly - this is where
// `dseditgroup -o edit -a <group> -t group <target>` actually stores a
// nested group's GUID, confirmed against a real CI run; it is NOT in
// GroupMembers alongside user members.
func TestParseDSCLAttrNestedGroups(t *testing.T) {
	// Modeled on real `dscl -read /Groups/<name> GroupMembership GroupMembers
	// NestedGroups` output: one line per requested attribute (continuation
	// lines, not exercised here, are indented and carry no "Attr:" prefix).
	out := "AppleMetaNodeLocation: /Local/Default\n" +
		"GroupMembership: alice bob\n" +
		"GroupMembers: \n" +
		"NestedGroups: ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050\n" +
		"PrimaryGroupID: 20\n" +
		"RecordName: com.apple.access_loginwindow\n" +
		"RecordType: dsRecTypeStandard:Groups\n"

	if got := parseDSCLAttr(out, "GroupMembership"); strings.Join(got, ",") != "alice,bob" {
		t.Fatalf("GroupMembership: got %v", got)
	}
	if got := parseDSCLAttr(out, "GroupMembers"); len(got) != 0 {
		t.Fatalf("GroupMembers: expected none, got %v", got)
	}
	if got := parseDSCLAttr(out, "NestedGroups"); strings.Join(got, ",") != "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050" {
		t.Fatalf("NestedGroups: got %v", got)
	}
}

// TestParseDSCLAttrNestedGroupsMultipleWithContinuationLine covers more than
// one NestedGroups GUID, including a wrapped continuation line (no "Attr:"
// prefix), the way dscl wraps long multi-value attributes.
func TestParseDSCLAttrNestedGroupsMultipleWithContinuationLine(t *testing.T) {
	out := "GroupMembership: \n" +
		"GroupMembers: \n" +
		"NestedGroups: ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050\n" +
		" FEDCBAFE-DCBA-FEDC-BAFE-DCBA00000099\n" +
		"RecordName: com.apple.access_loginwindow\n"

	got := parseDSCLAttr(out, "NestedGroups")
	if strings.Join(got, ",") != "ABCDEFAB-CDEF-ABCD-EFAB-CDEF00000050,FEDCBAFE-DCBA-FEDC-BAFE-DCBA00000099" {
		t.Fatalf("NestedGroups: got %v", got)
	}
}
