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
	Now    func() time.Time
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

// Suspend runs pre-flight, snapshots the current state, then applies the
// restriction. Repeating it while already suspended re-runs pre-flight (the
// invariant must still hold) and updates the banner/incident reference in
// place, without re-snapshotting (the original Previous is never lost).
func (m *Manager) Suspend(ctx context.Context, incidentID, commandID string) (string, error) {
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

	if so, err := m.Deps.SessionTerminator.SignOutNonAdmins(ctx, pre.EnabledLocalAdmins); err != nil {
		out = append(out, "sign-out: "+err.Error())
	} else {
		out = append(out, "sign-out: "+so)
	}

	detail, err := m.Deps.Backend.ApplyLogonRestriction(ctx, pre.EnabledLocalAdmins, rec.Previous.LogonRestriction)
	if err != nil {
		_ = m.delete()
		return "", fmt.Errorf("restricting sign-in: %w", err)
	}
	out = append(out, detail)

	ok, verifyDetail, err := m.Deps.Backend.VerifyStandardSignInBlocked(ctx, pre.EnabledLocalAdmins)
	if err != nil || !ok {
		_ = m.Deps.Backend.RestoreLogonRestriction(ctx, rec.Previous.LogonRestriction)
		_ = m.delete()
		if err != nil {
			return "", fmt.Errorf("verifying the restriction took effect: %w", err)
		}
		return "", fmt.Errorf("safety check failed, reverted: %s", verifyDetail)
	}
	out = append(out, verifyDetail)

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

// Restore puts back exactly the snapshot Suspend recorded. Repeating it when
// sign-in is not suspended is a no-op.
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
		return "", fmt.Errorf("restoring %s: %w", m.Deps.Backend.Name(), err)
	}
	out = append(out, "sign-in restriction restored")

	if err := m.Deps.Banner.Restore(ctx, rec.Previous.Banner); err != nil {
		out = append(out, "banner: FAILED to restore ("+err.Error()+")")
	} else {
		out = append(out, "banner cleared")
	}

	ok, verifyDetail, err := m.Deps.Backend.VerifyStandardSignInWorks(ctx, rec.Previous.LogonRestriction)
	switch {
	case err != nil:
		out = append(out, "verification: could not confirm ("+err.Error()+")")
	default:
		out = append(out, "verification: "+verifyDetail)
		_ = ok // reported in verifyDetail; restore itself already ran regardless
	}

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
