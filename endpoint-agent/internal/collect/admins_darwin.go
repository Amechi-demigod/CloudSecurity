//go:build darwin

package collect

import "context"

// AdminGroupMembers lists the local admin-group member names - the same
// source the local_admins posture check uses - for callers outside this
// package that need the raw list rather than a posture check (suspend-sign-in
// pre-flight).
func AdminGroupMembers(ctx context.Context) ([]string, error) {
	out, err := run(ctx, dsclBin, ".", "-read", "/Groups/admin", "GroupMembership")
	if err != nil {
		return nil, err
	}
	return parseGroupMembership(out), nil
}
