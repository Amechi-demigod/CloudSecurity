//go:build darwin

package signin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
)

const (
	dsclBin                 = "/usr/bin/dscl"
	dseditgroupBin          = "/usr/sbin/dseditgroup"
	launchctlBin            = "/bin/launchctl"
	accessLoginwindowRecord = "/Groups/com.apple.access_loginwindow"
	accessLoginwindowGroup  = "com.apple.access_loginwindow"
	localAdminGroup         = "admin"
)

// macMember is one GroupMembers (GUID-resolved) entry: a user or nested group
// by name, since dseditgroup adds/removes by name, not GUID.
type macMember struct {
	Name    string `json:"name"`
	IsGroup bool   `json:"is_group"`
}

// macLogonSnapshot is the macOS-specific Snapshot.LogonRestriction payload:
// whether com.apple.access_loginwindow existed and its exact membership
// before any change. system.login.console and other authorization rights are
// never touched by this backend - only this one group.
type macLogonSnapshot struct {
	GroupExisted bool        `json:"group_existed"`
	UserMembers  []string    `json:"user_members"`  // GroupMembership attribute: legacy short usernames
	Members      []macMember `json:"members"`       // GroupMembers attribute (GUIDs), resolved to name+type
	NestedGroups []string    `json:"nested_groups"` // NestedGroups attribute (GUIDs), resolved to group names - this is where dseditgroup -t group actually stores a nested group, NOT GroupMembers
}

func groupNotFound(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "edsrecordnotfound") || strings.Contains(lower, "no such key") ||
		strings.Contains(lower, "group not found") // dseditgroup's own message for a missing group
}

func parseDSCLAttr(out, attr string) []string {
	var vals []string
	on := false
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), attr+":"); ok {
			vals = append(vals, strings.Fields(v)...)
			on = true
			continue
		}
		if on {
			if strings.Contains(line, ":") {
				on = false
				continue
			}
			if t := strings.TrimSpace(line); t != "" {
				vals = append(vals, strings.Fields(t)...)
			}
		}
	}
	return vals
}

// resolveGUID resolves an Open Directory GeneratedUID to a record name,
// trying /Groups then /Users, since GroupMembers stores GUIDs for both.
//
// Uses `dscl -list <path> GeneratedUID` (every record's name + GUID, one
// per line) and an exact Go-side string comparison, rather than
// `dscl -search`, whose default match semantics (substring vs. exact,
// case sensitivity) are not reliably documented and proved unreliable here
// for comparing OD-stored GUIDs.
func resolveGUID(ctx context.Context, guid string) (macMember, bool) {
	if name, ok := lookupGeneratedUID(ctx, "/Groups", guid); ok {
		return macMember{Name: name, IsGroup: true}, true
	}
	if name, ok := lookupGeneratedUID(ctx, "/Users", guid); ok {
		return macMember{Name: name, IsGroup: false}, true
	}
	return macMember{}, false
}

func lookupGeneratedUID(ctx context.Context, path, guid string) (string, bool) {
	out, err := exec.CommandContext(ctx, dsclBin, ".", "-list", path, "GeneratedUID").CombinedOutput()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		// "<recordname> <GUID>" - the record name is everything before the
		// last field (names are typically a single token, but this is
		// robust either way since the GUID itself never contains spaces).
		if f[len(f)-1] == guid {
			return strings.Join(f[:len(f)-1], " "), true
		}
	}
	return "", false
}

// captureAccessLoginwindow reads com.apple.access_loginwindow's full
// membership: GroupMembership (legacy plain usernames), GroupMembers
// (GUID-based user/group members added via dseditgroup -t user, or in
// principle -t group though in practice group nesting lands in
// NestedGroups instead), and NestedGroups (GUIDs of groups nested via
// dseditgroup -t group - confirmed against a real CI run: this is where
// `dseditgroup -o edit -a <group> -t group <target>` actually stores the
// nested group, NOT GroupMembers).
func captureAccessLoginwindow(ctx context.Context) (macLogonSnapshot, error) {
	out, err := exec.CommandContext(ctx, dsclBin, ".", "-read", accessLoginwindowRecord,
		"GroupMembership", "GroupMembers", "NestedGroups").CombinedOutput()
	if err != nil {
		if groupNotFound(string(out)) {
			return macLogonSnapshot{GroupExisted: false}, nil
		}
		return macLogonSnapshot{}, fmt.Errorf("dscl -read %s: %v: %s", accessLoginwindowRecord, err, strings.TrimSpace(string(out)))
	}
	users := parseDSCLAttr(string(out), "GroupMembership")
	var members []macMember
	for _, guid := range parseDSCLAttr(string(out), "GroupMembers") {
		if m, ok := resolveGUID(ctx, guid); ok {
			members = append(members, m)
			continue
		}
		// Never silently drop an unresolved GUID: dseditgroup accepts a GUID
		// directly as a member identifier (per its own documentation), so
		// this is still usable for apply/restore even without a resolved
		// name, and keeping it visible here surfaces a resolution bug
		// immediately (as an unexpected member) instead of hiding it as a
		// phantom "0 members" state.
		members = append(members, macMember{Name: guid, IsGroup: true})
	}
	var nestedGroups []string
	for _, guid := range parseDSCLAttr(string(out), "NestedGroups") {
		if name, ok := lookupGeneratedUID(ctx, "/Groups", guid); ok {
			nestedGroups = append(nestedGroups, name)
			continue
		}
		nestedGroups = append(nestedGroups, guid) // unresolved: keep the raw GUID visible; still usable by dseditgroup
	}
	return macLogonSnapshot{GroupExisted: true, UserMembers: users, Members: members, NestedGroups: nestedGroups}, nil
}

func editMember(ctx context.Context, action, name, memberType string) error {
	out, err := exec.CommandContext(ctx, dseditgroupBin, "-o", "edit", action, name, "-t", memberType, accessLoginwindowGroup).CombinedOutput()
	if err == nil {
		return nil
	}
	s := strings.ToLower(string(out))
	if strings.Contains(s, "already a member") || strings.Contains(s, "not a member") {
		return nil // reconciling toward a target set: already-satisfied is success
	}
	return fmt.Errorf("dseditgroup -o edit %s %s -t %s: %v: %s", action, name, memberType, err, strings.TrimSpace(string(out)))
}

func addMember(ctx context.Context, name, memberType string) error {
	return editMember(ctx, "-a", name, memberType)
}
func removeMember(ctx context.Context, name, memberType string) error {
	return editMember(ctx, "-d", name, memberType)
}

// applyAccessLoginwindow restricts com.apple.access_loginwindow to the local
// admin group only. It is idempotent: driven by the group's CURRENT state
// (read fresh, not the original pre-suspend snapshot), so calling it again
// while already suspended reconciles toward the same target instead of
// trying to "-o create" a group that already exists (and failing). Creates
// the group first only if it does not currently exist. system.login.console
// and other authorization rights are never touched.
func applyAccessLoginwindow(ctx context.Context) (string, error) {
	cur, err := captureAccessLoginwindow(ctx)
	if err != nil {
		return "", fmt.Errorf("reading the current state of %s: %w", accessLoginwindowGroup, err)
	}
	if !cur.GroupExisted {
		if out, err := exec.CommandContext(ctx, dseditgroupBin, "-o", "create", accessLoginwindowGroup).CombinedOutput(); err != nil {
			return "", fmt.Errorf("dseditgroup -o create %s: %v: %s", accessLoginwindowGroup, err, strings.TrimSpace(string(out)))
		}
	} else {
		for _, u := range cur.UserMembers {
			if err := removeMember(ctx, u, "user"); err != nil {
				return "", err
			}
		}
		for _, m := range cur.Members {
			t := "user"
			if m.IsGroup {
				t = "group"
			}
			if err := removeMember(ctx, m.Name, t); err != nil {
				return "", err
			}
		}
		for _, g := range cur.NestedGroups {
			if g == localAdminGroup {
				continue // already the only nested group we want; nothing to remove
			}
			if err := removeMember(ctx, g, "group"); err != nil {
				return "", err
			}
		}
	}
	if err := addMember(ctx, localAdminGroup, "group"); err != nil {
		return "", err
	}
	return fmt.Sprintf("com.apple.access_loginwindow restricted to the local %s group", localAdminGroup), nil
}

// restoreAccessLoginwindow puts back exactly what was there before: deletes
// the group if it didn't exist, otherwise removes the admin-group member this
// backend added and restores every original member.
func restoreAccessLoginwindow(ctx context.Context, previous macLogonSnapshot) error {
	if !previous.GroupExisted {
		if out, err := exec.CommandContext(ctx, dseditgroupBin, "-o", "delete", accessLoginwindowGroup).CombinedOutput(); err != nil && !groupNotFound(string(out)) {
			return fmt.Errorf("dseditgroup -o delete %s: %v: %s", accessLoginwindowGroup, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := removeMember(ctx, localAdminGroup, "group"); err != nil {
		return err
	}
	for _, u := range previous.UserMembers {
		if err := addMember(ctx, u, "user"); err != nil {
			return err
		}
	}
	for _, m := range previous.Members {
		t := "user"
		if m.IsGroup {
			t = "group"
		}
		if err := addMember(ctx, m.Name, t); err != nil {
			return err
		}
	}
	for _, g := range previous.NestedGroups {
		if err := addMember(ctx, g, "group"); err != nil {
			return err
		}
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	s := map[string]bool{}
	for _, x := range a {
		s[x] = true
	}
	for _, x := range b {
		if !s[x] {
			return false
		}
	}
	return true
}

func sameMemberSet(a, b []macMember) bool {
	if len(a) != len(b) {
		return false
	}
	s := map[macMember]bool{}
	for _, x := range a {
		s[x] = true
	}
	for _, x := range b {
		if !s[x] {
			return false
		}
	}
	return true
}

type macBackend struct{}

func (macBackend) Name() string {
	return "macOS login window access group (com.apple.access_loginwindow)"
}

func (macBackend) CaptureLogonRestriction(ctx context.Context) (json.RawMessage, error) {
	snap, err := captureAccessLoginwindow(ctx)
	if err != nil {
		return nil, err
	}
	return json.Marshal(snap)
}

// ApplyLogonRestriction is the FIRST-TIME apply: on failure it attempts to
// restore com.apple.access_loginwindow to the pre-suspend snapshot and only
// reports success (via RolledBackError) once that restore is confirmed by a
// fresh read-back.
func (macBackend) ApplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (string, error) {
	var snap macLogonSnapshot
	if err := json.Unmarshal(previous, &snap); err != nil {
		return "", fmt.Errorf("corrupt logon-restriction snapshot: %w", err)
	}
	detail, applyErr := applyAccessLoginwindow(ctx)
	if applyErr == nil {
		return detail, nil
	}
	// Attempt to put com.apple.access_loginwindow back exactly, then RE-READ
	// it and confirm the restore actually matches the snapshot (not just that
	// the dseditgroup calls didn't error) before telling the caller it's safe
	// to treat this as a clean rollback.
	if rerr := restoreAccessLoginwindow(ctx, snap); rerr != nil {
		return "", fmt.Errorf("%w (rollback also failed: %v)", applyErr, rerr)
	}
	cur, verr := captureAccessLoginwindow(ctx)
	if verr != nil {
		return "", fmt.Errorf("%w (rollback verification failed: %v)", applyErr, verr)
	}
	if cur.GroupExisted != snap.GroupExisted || !sameStringSet(cur.UserMembers, snap.UserMembers) ||
		!sameMemberSet(cur.Members, snap.Members) || !sameStringSet(cur.NestedGroups, snap.NestedGroups) {
		return "", fmt.Errorf("%w (rollback did not restore the exact pre-suspend state)", applyErr)
	}
	return "", &RolledBackError{Err: applyErr}
}

// ReapplyLogonRestriction is used for a REPEAT Suspend or periodic Reenforce:
// it only reconciles toward the suspended target (applyAccessLoginwindow is
// itself idempotent, driven by current state) and NEVER restores the
// pre-suspend state on failure - the device must stay suspended.
func (macBackend) ReapplyLogonRestriction(ctx context.Context, adminNames []string, previous json.RawMessage) (string, error) {
	return applyAccessLoginwindow(ctx)
}

func (macBackend) RestoreLogonRestriction(ctx context.Context, previous json.RawMessage) error {
	var snap macLogonSnapshot
	if err := json.Unmarshal(previous, &snap); err != nil {
		return fmt.Errorf("corrupt logon-restriction snapshot: %w", err)
	}
	return restoreAccessLoginwindow(ctx, snap)
}

func (macBackend) VerifyStandardSignInBlocked(ctx context.Context, adminNames []string) (bool, string, error) {
	cur, err := captureAccessLoginwindow(ctx)
	if err != nil {
		return false, "", err
	}
	if !cur.GroupExisted {
		return false, "com.apple.access_loginwindow does not exist after applying the restriction", nil
	}
	if len(cur.UserMembers) != 0 {
		return false, fmt.Sprintf("com.apple.access_loginwindow has unexpected user member(s): %s", strings.Join(cur.UserMembers, ", ")), nil
	}
	if len(cur.Members) != 0 {
		return false, fmt.Sprintf("com.apple.access_loginwindow has unexpected GroupMembers entries: %+v", cur.Members), nil
	}
	if len(cur.NestedGroups) != 1 || cur.NestedGroups[0] != localAdminGroup {
		return false, fmt.Sprintf("com.apple.access_loginwindow's nested groups are not exactly the local admin "+
			"group (found: %v)", cur.NestedGroups), nil
	}
	return true, fmt.Sprintf("com.apple.access_loginwindow restricts console sign-in to the local %s group", localAdminGroup), nil
}

func (macBackend) VerifyStandardSignInWorks(ctx context.Context, previous json.RawMessage) (bool, string, error) {
	var want macLogonSnapshot
	if err := json.Unmarshal(previous, &want); err != nil {
		return false, "", err
	}
	got, err := captureAccessLoginwindow(ctx)
	if err != nil {
		return false, "", err
	}
	if got.GroupExisted != want.GroupExisted {
		return false, "com.apple.access_loginwindow existence does not match the pre-suspend snapshot", nil
	}
	if !want.GroupExisted {
		return true, "com.apple.access_loginwindow did not exist before suspending and does not exist now", nil
	}
	if !sameStringSet(got.UserMembers, want.UserMembers) || !sameMemberSet(got.Members, want.Members) ||
		!sameStringSet(got.NestedGroups, want.NestedGroups) {
		return false, "com.apple.access_loginwindow's membership does not match the pre-suspend snapshot", nil
	}
	return true, "com.apple.access_loginwindow matches the pre-suspend snapshot", nil
}

// consoleUser duplicates internal/commands/lock_darwin.go's ~10-line logic
// (unexported there, a different package).
func consoleUser() (int, string) {
	st, err := os.Stat("/dev/console")
	if err != nil {
		return 0, ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, ""
	}
	name := strconv.Itoa(int(sys.Uid))
	if u, err := user.LookupId(name); err == nil {
		name = u.Username
	}
	return int(sys.Uid), name
}

type macSessionTerminator struct{}

// SignOutNonAdmins tears down the console user's GUI session with
// `launchctl bootout gui/<uid>` from the root LaunchDaemon context, unless
// the console user is a local admin. NEEDS VALIDATION on a real Mac: confirm
// this actually returns the session to the login window.
func (macSessionTerminator) SignOutNonAdmins(ctx context.Context, adminNames []string) (string, error) {
	uid, name := consoleUser()
	if uid == 0 {
		return "no console user; nothing to sign out", nil
	}
	for _, a := range adminNames {
		if strings.EqualFold(a, name) {
			return fmt.Sprintf("console user %s is a local admin; not signed out", name), nil
		}
	}
	out, err := exec.CommandContext(ctx, launchctlBin, "bootout", fmt.Sprintf("gui/%d", uid)).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("launchctl bootout gui/%d: %v: %s", uid, err, strings.TrimSpace(string(out)))
	}
	return fmt.Sprintf("console user %s (uid %d) signed out (launchctl bootout)", name, uid), nil
}

type macAdminProbe struct{}

func (macAdminProbe) EnabledLocalAdmins(ctx context.Context) ([]string, error) {
	return collect.AdminGroupMembers(ctx)
}

func platformBackend() Backend                     { return macBackend{} }
func platformAdminProbe() AdminProbe               { return macAdminProbe{} }
func platformLAPSProbe() LAPSProbe                 { return nil }
func platformSessionTerminator() SessionTerminator { return macSessionTerminator{} }
