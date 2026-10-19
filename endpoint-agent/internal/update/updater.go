package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
)

// Status values reported to the server (POST /api/agent/updates/status).
const (
	StatusDownloading = "downloading"
	StatusVerified    = "verified"
	StatusInstalling  = "installing"
	StatusInstalled   = "installed"
	StatusRolledBack  = "rolled_back"
	StatusFailed      = "failed"
	StatusRejected    = "rejected"
)

// Phases of update.json's pending update.
const (
	PhaseSwapped    = "swapped"     // new binary in place, waiting for a healthy check-in
	PhaseHealthy    = "healthy"     // new binary checked in successfully
	PhaseRolledBack = "rolled_back" // previous binary restored
)

// StateFileName is the update state document in the agent's state directory.
const StateFileName = "update.json"

// Health-check bounds (the server suggests a value per offer).
const (
	DefaultHealthTimeout = 10 * time.Minute
	MinHealthTimeout     = time.Minute
	MaxHealthTimeout     = time.Hour
	// A new binary that keeps restarting without becoming healthy restores the
	// previous one itself (in case the watchdog process is gone, e.g. after a reboot).
	MaxStartsBeforeSelfRollback = 5
	maxFailedRemembered         = 20
)

// ErrRestartRequired is returned by Apply after the binary was swapped: the
// caller must exit so the service manager starts the new binary.
var ErrRestartRequired = errors.New("agent binary replaced; restart required")

// Offer is what the server proposes at check-in ("update" in the response).
type Offer struct {
	ReleaseID            string `json:"release_id"`
	Version              string `json:"version"`
	ManifestPath         string `json:"manifest_path"`
	ArtifactPath         string `json:"artifact_path"`
	HealthTimeoutSeconds int    `json:"health_timeout_seconds"`
	JitterSeconds        int    `json:"jitter_seconds"`
}

// Report is one status update for the server.
type Report struct {
	ReleaseID   string `json:"release_id,omitempty"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Status      string `json:"status"`
	Detail      string `json:"detail,omitempty"`
}

// Transport is the agent API (implemented by client.Client).
type Transport interface {
	// Fetch GETs an /api/agent/updates/ path into w, reading at most max bytes.
	Fetch(ctx context.Context, path string, max int64, w io.Writer) (int64, error)
	ReportUpdate(ctx context.Context, r Report) error
}

// Platform hooks (OS-specific; replaced by fakes in tests).
type Platform interface {
	// VerifyBinary checks OS code signing (Authenticode / codesign) when the
	// build requires it; nil when not configured.
	VerifyBinary(path string) error
	// Preflight runs `<path> version` and checks it prints wantVersion.
	Preflight(ctx context.Context, path, wantVersion string) error
	// StartWatchdog starts `<binary> update-watchdog <args>` detached from the
	// service so it survives the agent's exit.
	StartWatchdog(binary string, args []string) error
	// RestartService restarts the agent service with the binary now in place.
	RestartService() error
}

// Pending describes an update in progress (or its outcome until reported).
type Pending struct {
	Phase       string    `json:"phase"`
	ReleaseID   string    `json:"release_id"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	BinaryPath  string    `json:"binary_path"`
	BackupPath  string    `json:"backup_path"`
	SwappedAt   time.Time `json:"swapped_at"`
	Deadline    time.Time `json:"deadline"`
	Starts      int       `json:"starts"`
	Reason      string    `json:"reason,omitempty"`
	Reported    bool      `json:"reported"`
}

// FailedRelease is a release this device will not try again.
type FailedRelease struct {
	ReleaseID string    `json:"release_id"`
	Version   string    `json:"version"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

// File is update.json.
type File struct {
	Pending *Pending        `json:"pending,omitempty"`
	Failed  []FailedRelease `json:"failed,omitempty"`
}

// Updater applies signed updates to the agent binary.
type Updater struct {
	Keys       []TrustedKey
	Current    string // running version
	GOOS       string
	GOARCH     string
	BinaryPath string // installed binary (replaced in place)
	Paths      state.Paths
	Transport  Transport
	Platform   Platform
	Now        func() time.Time
	// WatchdogArgs are passed to `update-watchdog` (e.g. --home DIR).
	WatchdogArgs []string
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

// SidePath returns the staging (new), backup (old) and failed paths next to
// the binary. On Windows the suffix goes before ".exe" so they stay executable.
func SidePath(bin, kind string) string {
	ext := filepath.Ext(bin)
	if strings.EqualFold(ext, ".exe") {
		return strings.TrimSuffix(bin, ext) + "." + kind + ext
	}
	return bin + "." + kind
}

// LoadFile reads update.json (empty if missing or unreadable).
func LoadFile(p state.Paths) File {
	var f File
	if b, err := os.ReadFile(filepath.Join(p.StateDir, StateFileName)); err == nil {
		if err := json.Unmarshal(b, &f); err != nil {
			slog.Warn("ignoring corrupt update state", "err", err)
			return File{}
		}
	}
	return f
}

// SaveFile writes update.json with the state file's protections.
func SaveFile(p state.Paths, f File) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return state.WriteFile(p, StateFileName, b)
}

func (f *File) failed(releaseID string) *FailedRelease {
	for i := range f.Failed {
		if f.Failed[i].ReleaseID == releaseID {
			return &f.Failed[i]
		}
	}
	return nil
}

func (f *File) markFailed(releaseID, version, reason string, at time.Time) {
	if releaseID == "" || f.failed(releaseID) != nil {
		return
	}
	f.Failed = append(f.Failed, FailedRelease{ReleaseID: releaseID, Version: version, Reason: truncate(reason, 500), At: at.UTC()})
	if len(f.Failed) > maxFailedRemembered {
		f.Failed = f.Failed[len(f.Failed)-maxFailedRemembered:]
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (u *Updater) report(ctx context.Context, r Report) {
	if r.FromVersion == "" {
		r.FromVersion = u.Current
	}
	r.Detail = truncate(r.Detail, 2000)
	if err := u.Transport.ReportUpdate(ctx, r); err != nil {
		slog.Warn("reporting update status failed", "status", r.Status, "err", err)
	}
}

// HealthTimeout bounds the server-suggested health-check window.
func HealthTimeout(seconds int) time.Duration {
	d := time.Duration(seconds) * time.Second
	switch {
	case seconds <= 0:
		return DefaultHealthTimeout
	case d < MinHealthTimeout:
		return MinHealthTimeout
	case d > MaxHealthTimeout:
		return MaxHealthTimeout
	}
	return d
}

// Apply downloads, verifies and installs an offered release. It returns
// ErrRestartRequired after a successful swap, nil when there is nothing to do,
// or an error (already reported to the server where useful).
func (u *Updater) Apply(ctx context.Context, o Offer) error {
	f := LoadFile(u.Paths)
	if f.Pending != nil && f.Pending.Phase == PhaseSwapped {
		return nil // an update is already being health-checked
	}
	if fr := f.failed(o.ReleaseID); fr != nil {
		slog.Info("not retrying a release that failed on this device", "version", fr.Version, "reason", fr.Reason)
		return nil
	}
	log := slog.With("release_id", o.ReleaseID, "version", o.Version)
	reject := func(err error) error {
		log.Error("update rejected", "err", err)
		f := LoadFile(u.Paths)
		f.markFailed(o.ReleaseID, o.Version, err.Error(), u.now())
		if serr := SaveFile(u.Paths, f); serr != nil {
			log.Warn("could not record the failed release", "err", serr)
		}
		u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: o.Version, Status: StatusRejected, Detail: err.Error()})
		return err
	}
	if !strings.HasPrefix(o.ManifestPath, "/api/agent/updates/") || !strings.HasPrefix(o.ArtifactPath, "/api/agent/updates/") {
		return reject(errors.New("offer points outside /api/agent/updates/"))
	}

	// 1. Manifest: signature, expiry, version policy, platform.
	var mb strings.Builder
	if _, err := u.Transport.Fetch(ctx, o.ManifestPath, MaxManifestBytes, &mb); err != nil {
		return fmt.Errorf("fetching the manifest: %w", err) // transient: retried at a later check-in
	}
	m, err := Verify([]byte(mb.String()), u.Keys, u.now())
	if err != nil {
		return reject(err)
	}
	if m.Version != o.Version {
		return reject(fmt.Errorf("%w: offered %s, manifest says %s", ErrVersionMismatch, o.Version, m.Version))
	}
	art, err := m.Check(u.Current, u.GOOS, u.GOARCH)
	if errors.Is(err, ErrSameVersion) {
		return nil
	}
	if err != nil {
		return reject(err)
	}
	log.Info("verified signed update manifest", "key_id", m.KeyID, "artifact", art.Name, "size", art.Size)

	// 2. Artifact: download next to the binary, check size and SHA-256.
	u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: m.Version, Status: StatusDownloading})
	newPath := SidePath(u.BinaryPath, "new")
	if err := download(ctx, u.Transport, o.ArtifactPath, newPath, art); err != nil {
		_ = os.Remove(newPath)
		if errors.Is(err, ErrHashMismatch) || errors.Is(err, ErrSizeMismatch) {
			return reject(err)
		}
		u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: m.Version, Status: StatusFailed,
			Detail: "download failed (will retry): " + err.Error()})
		return fmt.Errorf("downloading the artifact: %w", err)
	}
	if err := u.Platform.VerifyBinary(newPath); err != nil {
		_ = os.Remove(newPath)
		return reject(fmt.Errorf("platform code signature: %w", err))
	}
	if err := u.Platform.Preflight(ctx, newPath, m.Version); err != nil {
		_ = os.Remove(newPath)
		return reject(fmt.Errorf("pre-flight check of the new binary: %w", err))
	}
	u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: m.Version, Status: StatusVerified,
		Detail: fmt.Sprintf("signature %s, sha256 %s, %d bytes", m.KeyID, art.SHA256, art.Size)})

	// 3. Swap: current -> backup, new -> current. Then record the pending
	// update, start the watchdog (running the OLD binary) and restart.
	backup := SidePath(u.BinaryPath, "old")
	if err := swap(u.BinaryPath, newPath, backup); err != nil {
		_ = os.Remove(newPath)
		u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: m.Version, Status: StatusFailed, Detail: "swap: " + err.Error()})
		return err
	}
	now := u.now().UTC()
	f = LoadFile(u.Paths)
	f.Pending = &Pending{Phase: PhaseSwapped, ReleaseID: o.ReleaseID, FromVersion: u.Current, ToVersion: m.Version,
		BinaryPath: u.BinaryPath, BackupPath: backup, SwappedAt: now,
		Deadline: now.Add(HealthTimeout(o.HealthTimeoutSeconds))}
	undo := func(cause error) error {
		if rerr := restore(u.BinaryPath, backup, SidePath(u.BinaryPath, "failed")); rerr != nil {
			log.Error("could not undo the swap", "err", rerr)
		}
		f := LoadFile(u.Paths)
		f.Pending = nil
		_ = SaveFile(u.Paths, f)
		u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: m.Version, Status: StatusFailed, Detail: cause.Error()})
		return cause
	}
	if err := SaveFile(u.Paths, f); err != nil {
		return undo(fmt.Errorf("saving update state: %w", err))
	}
	if err := u.Platform.StartWatchdog(backup, u.WatchdogArgs); err != nil {
		return undo(fmt.Errorf("starting the rollback watchdog: %w", err))
	}
	u.report(ctx, Report{ReleaseID: o.ReleaseID, ToVersion: m.Version, Status: StatusInstalling,
		Detail: fmt.Sprintf("binary replaced; restarting (health check within %s)", HealthTimeout(o.HealthTimeoutSeconds))})
	log.Info("agent binary replaced; restarting into the new version")
	return ErrRestartRequired
}

func download(ctx context.Context, t Transport, path, dst string, art *Artifact) error {
	_ = os.Remove(dst)
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := t.Fetch(ctx, path, art.Size, io.MultiWriter(out, h))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != art.Size {
		return fmt.Errorf("%w: got %d bytes, manifest says %d", ErrSizeMismatch, n, art.Size)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != art.SHA256 {
		return fmt.Errorf("%w: got %s", ErrHashMismatch, got)
	}
	return os.Chmod(dst, 0o755)
}

// swap moves bin to backup and newPath to bin (renames on the same volume;
// Windows allows renaming a running executable, not overwriting it).
func swap(bin, newPath, backup string) error {
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing the previous backup: %w", err)
	}
	if err := os.Rename(bin, backup); err != nil {
		return fmt.Errorf("backing up the current binary: %w", err)
	}
	if err := os.Rename(newPath, bin); err != nil {
		if rerr := os.Rename(backup, bin); rerr != nil {
			return fmt.Errorf("installing the new binary: %v; restoring the backup also failed: %w", err, rerr)
		}
		return fmt.Errorf("installing the new binary: %w", err)
	}
	return nil
}

// restore puts the backup back in place: bin -> failed, copy backup -> bin.
// The backup is copied (not moved) because the watchdog runs from it.
func restore(bin, backup, failed string) error {
	if _, err := os.Stat(backup); err != nil {
		return fmt.Errorf("backup binary: %w", err)
	}
	tmp := SidePath(bin, "restore")
	_ = os.Remove(tmp)
	if err := copyFile(backup, tmp); err != nil {
		return err
	}
	_ = os.Remove(failed)
	if err := os.Rename(bin, failed); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return fmt.Errorf("moving the failed binary aside: %w", err)
	}
	if err := os.Rename(tmp, bin); err != nil {
		return fmt.Errorf("restoring the previous binary: %w", err)
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// OnStart runs before the agent loop. It counts starts of a freshly swapped
// binary and, when it keeps failing before ever becoming healthy (and no
// watchdog acted), restores the previous binary itself. It returns true when
// the caller must exit so the service manager starts the restored binary.
func (u *Updater) OnStart() bool {
	f := LoadFile(u.Paths)
	p := f.Pending
	if p == nil || p.Phase != PhaseSwapped {
		return false
	}
	switch u.Current {
	case p.ToVersion:
		p.Starts++
		if p.Starts > MaxStartsBeforeSelfRollback {
			slog.Error("new agent version keeps restarting without a healthy check-in; restoring the previous version",
				"version", u.Current, "starts", p.Starts)
			if err := restore(p.BinaryPath, p.BackupPath, SidePath(p.BinaryPath, "failed")); err != nil {
				slog.Error("self-rollback failed", "err", err)
				_ = SaveFile(u.Paths, f)
				return false
			}
			p.Phase = PhaseRolledBack
			p.Reason = fmt.Sprintf("version %s restarted %d times without a successful check-in", p.ToVersion, p.Starts-1)
			_ = SaveFile(u.Paths, f)
			return true
		}
		_ = SaveFile(u.Paths, f)
	case p.FromVersion:
		// The previous binary is running again although nobody marked a
		// rollback (e.g. an MSI repair restored it): treat as rolled back.
		p.Phase = PhaseRolledBack
		p.Reason = "the previous version is running again (binary restored outside the updater)"
		_ = SaveFile(u.Paths, f)
	}
	return false
}

// MarkHealthy is called after a successful check-in.
func (u *Updater) MarkHealthy() {
	f := LoadFile(u.Paths)
	p := f.Pending
	if p == nil || p.Phase != PhaseSwapped || u.Current != p.ToVersion {
		return
	}
	p.Phase = PhaseHealthy
	p.Reason = fmt.Sprintf("checked in successfully %s after the swap", u.now().Sub(p.SwappedAt).Round(time.Second))
	if err := SaveFile(u.Paths, f); err != nil {
		slog.Warn("could not record the healthy update", "err", err)
		return
	}
	_ = os.Remove(SidePath(p.BinaryPath, "failed"))
	slog.Info("update healthy", "version", p.ToVersion, "previous", p.FromVersion)
}

// ReportOutcome sends the final status (installed / rolled_back) once.
func (u *Updater) ReportOutcome(ctx context.Context) {
	f := LoadFile(u.Paths)
	p := f.Pending
	if p == nil || p.Reported || (p.Phase != PhaseHealthy && p.Phase != PhaseRolledBack) {
		return
	}
	r := Report{ReleaseID: p.ReleaseID, FromVersion: p.FromVersion, ToVersion: p.ToVersion, Detail: p.Reason}
	if p.Phase == PhaseHealthy {
		r.Status = StatusInstalled
	} else {
		r.Status = StatusRolledBack
		f.markFailed(p.ReleaseID, p.ToVersion, "rolled back: "+p.Reason, u.now())
	}
	if err := u.Transport.ReportUpdate(ctx, r); err != nil {
		slog.Warn("reporting the update outcome failed; will retry", "status", r.Status, "err", err)
		_ = SaveFile(u.Paths, f)
		return
	}
	p.Reported = true
	if err := SaveFile(u.Paths, f); err != nil {
		slog.Warn("could not save update state", "err", err)
	}
}

// Watchdog runs as a detached process from the PREVIOUS binary (the backup).
// If the new binary does not report a healthy check-in before the deadline,
// it restores the previous binary and restarts the service.
func (u *Updater) Watchdog(ctx context.Context, poll time.Duration) error {
	for {
		f := LoadFile(u.Paths)
		p := f.Pending
		if p == nil || p.Phase != PhaseSwapped {
			slog.Info("update watchdog: nothing to watch", "phase", phaseOf(p))
			return nil
		}
		if !u.now().Before(p.Deadline) {
			slog.Error("update watchdog: new version not healthy in time; rolling back",
				"version", p.ToVersion, "previous", p.FromVersion, "deadline", p.Deadline)
			if err := restore(p.BinaryPath, p.BackupPath, SidePath(p.BinaryPath, "failed")); err != nil {
				return fmt.Errorf("rollback: %w", err)
			}
			p.Phase = PhaseRolledBack
			p.Reason = fmt.Sprintf("health check failed: no successful check-in from %s within %s",
				p.ToVersion, p.Deadline.Sub(p.SwappedAt).Round(time.Second))
			if err := SaveFile(u.Paths, f); err != nil {
				slog.Error("update watchdog: saving state failed", "err", err)
			}
			if err := u.Platform.RestartService(); err != nil {
				return fmt.Errorf("restarting the service after rollback: %w", err)
			}
			slog.Info("update watchdog: previous version restored and service restarted", "version", p.FromVersion)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

func phaseOf(p *Pending) string {
	if p == nil {
		return "none"
	}
	return p.Phase
}
