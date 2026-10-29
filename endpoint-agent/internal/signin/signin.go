// Package signin implements "Suspend sign-in" / "Restore sign-in": an
// incident-containment action that signs out a managed device's non-admin
// users and blocks standard interactive sign-in, while leaving local admin
// access working so IT can recover the device. It is not network isolation:
// nothing here touches network connectivity.
//
// Safety comes first: a pre-flight check refuses to suspend sign-in unless at
// least one enabled local administrator account would remain able to sign in
// (ErrNoLocalAdminPresent), and every change is snapshotted before it is made
// so Restore sign-in can put the device back exactly as it was.
package signin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/lostmode"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// ErrNoLocalAdminPresent is returned by Preflight/Suspend when no enabled
// local administrator account was found: suspending sign-in would risk
// locking everyone out, so nothing is changed.
var ErrNoLocalAdminPresent = errors.New("ERR_NO_LOCAL_ADMIN_PRESENT")

// PreflightResult is what the pre-flight check found.
type PreflightResult struct {
	EnabledLocalAdmins []string
	LAPS               *LAPSStatus // nil on macOS, or when the probe itself failed
}

// Deps are the platform-specific collaborators a Manager needs.
type Deps struct {
	AdminProbe        AdminProbe
	LAPSProbe         LAPSProbe // nil on non-Windows
	SessionTerminator SessionTerminator
	Backend           Backend
	// Banner reuses lostmode's registry/defaults Get/Set/Restore mechanism
	// for the sign-in-screen message, injected (not called directly via
	// lostmode.PlatformBackend()) so tests can supply a fake instead of
	// touching real OS state.
	Banner lostmode.Backend
	// LostMode reports whether lost mode is active, so Suspend can refuse to
	// run alongside it. Nil disables the check (tests only); New() always
	// wires a real one.
	LostMode LostModeChecker
	Now      func() time.Time
}

type lostModeAdapter struct{ m *lostmode.Manager }

func (a lostModeAdapter) Active(ctx context.Context) (bool, error) {
	rec, err := a.m.Load()
	if err != nil {
		return false, err
	}
	return rec != nil, nil
}

// Manager applies and clears suspend-sign-in.
type Manager struct {
	Paths state.Paths
	Deps  Deps
}

// New returns a Manager wired with the platform backends.
func New(p state.Paths) *Manager {
	return &Manager{Paths: p, Deps: Deps{
		AdminProbe:        platformAdminProbe(),
		LAPSProbe:         platformLAPSProbe(),
		SessionTerminator: platformSessionTerminator(),
		Backend:           platformBackend(),
		Banner:            lostmode.PlatformBackend(),
		LostMode:          lostModeAdapter{m: lostmode.New(p, nil)},
		Now:               time.Now,
	}}
}

func (m *Manager) file() string { return filepath.Join(m.Paths.StateDir, StateFileName) }

// Load returns the current record (nil when sign-in is not suspended).
func (m *Manager) Load() (*Record, error) {
	b, err := os.ReadFile(m.file())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("corrupt %s: %w", m.file(), err)
	}
	if !r.Active {
		return nil, nil
	}
	return &r, nil
}

func (m *Manager) save(r *Record) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFile(m.Paths, StateFileName, b)
}

func (m *Manager) delete() error {
	if err := os.Remove(m.file()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Preflight checks that suspending sign-in would not lock everyone out, and
// reports LAPS telemetry (Windows only, config/policy only - never a
// password). Nothing is written or changed; a transport/probe error (could
// not tell whether an admin exists) is reported distinctly from "checked,
// found none".
func (m *Manager) Preflight(ctx context.Context) (PreflightResult, error) {
	admins, err := m.Deps.AdminProbe.EnabledLocalAdmins(ctx)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("could not enumerate local administrators: %w", err)
	}
	if len(admins) == 0 {
		return PreflightResult{}, ErrNoLocalAdminPresent
	}
	res := PreflightResult{EnabledLocalAdmins: admins}
	if m.Deps.LAPSProbe != nil {
		if laps, err := m.Deps.LAPSProbe.Status(ctx); err == nil {
			res.LAPS = &laps
		} else {
			res.LAPS = &LAPSStatus{Detail: "could not determine LAPS configuration: " + err.Error()}
		}
	}
	return res, nil
}

// composeBanner builds the sign-in-screen message, reusing lostmode.Notice.
func composeBanner(incidentID string) lostmode.Notice {
	text := "Sign-in is suspended. Contact IT/Security."
	if incidentID != "" {
		text += " Reference: " + incidentID
	}
	return lostmode.Notice{
		Caption: "This device has been suspended", CaptionSet: true,
		Text: text, TextSet: true,
	}
}

// Suspend runs pre-flight, snapshots the current state, then restricts sign-in
// and verifies it took effect BEFORE signing anyone out - a failed or unsafe
// restriction must never sign anyone out. Repeating it while already
// suspended re-runs pre-flight (the invariant must still hold) and updates
// the banner/incident reference in place, without re-snapshotting (the
// original Previous is never lost).
func (m *Manager) Suspend(ctx context.Context, incidentID, commandID string) (string, error) {
	if m.Deps.LostMode != nil {
		active, err := m.Deps.LostMode.Active(ctx)
		if err != nil {
			return "", fmt.Errorf("checking lost mode state: %w", err)
		}
		if active {
			return "", errors.New("cannot suspend sign-in: lost mode is already active on this device; exit lost mode first")
		}
	}

	pre, err := m.Preflight(ctx)
	if err != nil {
		return "", err
	}

	rec, err := m.Load()
	if err != nil {
		return "", err
	}

	var out []string
	if rec != nil {
		out = append(out, "sign-in was already suspended; incident reference and admin list updated")
		rec.IncidentID, rec.CommandID = incidentID, commandID
		rec.AdminsAtTime = pre.EnabledLocalAdmins
		rec.LAPS = pre.LAPS
	} else {
		prevLogon, err := m.Deps.Backend.CaptureLogonRestriction(ctx)
		if err != nil {
			return "", fmt.Errorf("reading the current %s: %w", m.Deps.Backend.Name(), err)
		}
		prevBanner, err := m.Deps.Banner.Get(ctx)
		if err != nil {
			return "", fmt.Errorf("reading the current sign-in banner: %w", err)
		}
		rec = &Record{
			Active: true, IncidentID: incidentID, CommandID: commandID, Since: m.now().UTC(),
			AdminsAtTime: pre.EnabledLocalAdmins, LAPS: pre.LAPS,
			Previous: Snapshot{LogonRestriction: prevLogon, Banner: prevBanner},
		}
	}

	// Persist first: a crash after changing anything live must still be
	// reversible from what's on disk right now.
	rec.Pending = &Pending{Phase: PhaseSnapshotting, StartedAt: m.now().UTC()}
	if err := m.save(rec); err != nil {
		_ = m.delete() // the write itself failed; nothing live has changed, leave nothing behind
		return "", fmt.Errorf("saving the suspend-sign-in record: %w", err)
	}

	rec.Pending.Phase = PhaseApplying
	if err := m.save(rec); err != nil {
		return "", fmt.Errorf("saving the suspend-sign-in record: %w", err)
	}

	// Restrict, then verify, BEFORE signing anyone out: a failed or unsafe
	// apply must leave every session exactly as it was.
	detail, err := m.Deps.Backend.ApplyLogonRestriction(ctx, pre.EnabledLocalAdmins, rec.Previous.LogonRestriction)
	if err != nil {
		var rb *RolledBackError
		if errors.As(err, &rb) {
			// The backend confirmed it undid everything it had changed:
			// the live state matches the snapshot, safe to delete.
			_ = m.delete()
			return "", fmt.Errorf("restricting sign-in: %w", err)
		}
		rec.Pending.LastError = err.Error()
		if serr := m.save(rec); serr != nil {
			return "", fmt.Errorf("restricting sign-in: %w (and the record could not be updated: %v)", err, serr)
		}
		return "", fmt.Errorf("restricting sign-in: %w; the rollback could not be confirmed, the device may be "+
			"left partially restricted - manual recovery may be required", err)
	}
	out = append(out, detail)

	ok, verifyDetail, err := m.Deps.Backend.VerifyStandardSignInBlocked(ctx, pre.EnabledLocalAdmins)
	if err != nil || !ok {
		rerr := m.Deps.Backend.RestoreLogonRestriction(ctx, rec.Previous.LogonRestriction)
		if rerr != nil {
			rec.Pending.LastError = fmt.Sprintf("safety check (ok=%v err=%v detail=%s); rollback failed: %v", ok, err, verifyDetail, rerr)
			if serr := m.save(rec); serr != nil {
				return "", fmt.Errorf("safety check failed and the rollback also failed (%v) (and the record could "+
					"not be updated: %v): manual recovery required", rerr, serr)
			}
			return "", fmt.Errorf("safety check failed and the rollback also failed (%v): the device may be left "+
				"partially restricted; manual recovery required", rerr)
		}
		_ = m.delete()
		if err != nil {
			return "", fmt.Errorf("verifying the restriction took effect: %w", err)
		}
		return "", fmt.Errorf("safety check failed, reverted: %s", verifyDetail)
	}
	out = append(out, verifyDetail)

	// Only now, with the restriction verified safe, sign non-admins out.
	if so, err := m.Deps.SessionTerminator.SignOutNonAdmins(ctx, pre.EnabledLocalAdmins); err != nil {
		out = append(out, "sign-out: "+err.Error())
	} else {
		out = append(out, "sign-out: "+so)
	}

	if err := m.Deps.Banner.Set(ctx, composeBanner(incidentID)); err != nil {
		out = append(out, "banner: FAILED to set ("+err.Error()+")")
	} else {
		out = append(out, "banner: sign-in message set")
	}

	rec.Pending.Phase = PhaseApplied
	if err := m.save(rec); err != nil {
		return "", fmt.Errorf("saving the suspend-sign-in record: %w", err)
	}

	return strings.Join(out, "\n"), nil
}

// Restore puts back exactly the snapshot Suspend recorded. The record is only
// deleted once that is VERIFIED: a restore whose effect can't be confirmed
// (VerifyStandardSignInWorks errors or reports a mismatch) keeps the record
// so a human or a future crash-recovery pass can resolve it. Repeating it
// when sign-in is not suspended is a no-op.
func (m *Manager) Restore(ctx context.Context) (string, error) {
	rec, err := m.Load()
	if err != nil {
		return "", err
	}
	if rec == nil {
		return "sign-in was not suspended; nothing to restore", nil
	}

	rec.Pending = &Pending{Phase: PhaseRestoring, StartedAt: m.now().UTC()}
	if err := m.save(rec); err != nil {
		return "", fmt.Errorf("saving the suspend-sign-in record: %w", err)
	}

	var out []string
	if err := m.Deps.Backend.RestoreLogonRestriction(ctx, rec.Previous.LogonRestriction); err != nil {
		rec.Pending.LastError = err.Error()
		_ = m.save(rec)
		return "", fmt.Errorf("restoring %s: %w", m.Deps.Backend.Name(), err)
	}
	out = append(out, "sign-in restriction restored")

	if err := m.Deps.Banner.Restore(ctx, rec.Previous.Banner); err != nil {
		out = append(out, "banner: FAILED to restore ("+err.Error()+")")
	} else {
		out = append(out, "banner cleared")
	}

	ok, verifyDetail, err := m.Deps.Backend.VerifyStandardSignInWorks(ctx, rec.Previous.LogonRestriction)
	if err != nil || !ok {
		rec.Pending.LastError = fmt.Sprintf("restore verification: ok=%v err=%v detail=%s", ok, err, verifyDetail)
		if serr := m.save(rec); serr != nil {
			return "", fmt.Errorf("restoring %s: verification failed (and the record could not be updated: %v)",
				m.Deps.Backend.Name(), serr)
		}
		if err != nil {
			return "", fmt.Errorf("restoring %s: the restriction was written back but could not be verified: %w",
				m.Deps.Backend.Name(), err)
		}
		return "", fmt.Errorf("restoring %s: the restriction was written back but does not match the pre-suspend "+
			"snapshot: %s", m.Deps.Backend.Name(), verifyDetail)
	}
	out = append(out, "verification: "+verifyDetail)

	if err := m.delete(); err != nil {
		return "", err
	}
	return strings.Join(out, "\n"), nil
}

func (m *Manager) now() time.Time {
	if m.Deps.Now != nil {
		return m.Deps.Now()
	}
	return time.Now()
}
