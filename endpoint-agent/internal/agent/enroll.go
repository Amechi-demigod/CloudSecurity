package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/backoff"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/client"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

// EnrollOptions are the `cnapp-agent enroll` flags.
type EnrollOptions struct {
	Server      string
	Token       string
	InsecureDev bool
	CAFile      string // PEM bundle of a private CA, copied into the state directory
	CAPEM       []byte // same, in memory (from an installer's enroll.json); wins over CAFile
}

// Enroll exchanges an enrollment token for a device credential and stores it.
// Running it again re-enrolls (the server rotates the credential).
func Enroll(ctx context.Context, p state.Paths, o EnrollOptions) (*client.EnrollResponse, error) {
	server, err := state.ValidateServerURL(o.Server, o.InsecureDev)
	if err != nil {
		return nil, err
	}
	caPEM := o.CAPEM
	if len(caPEM) == 0 && o.CAFile != "" {
		if caPEM, err = os.ReadFile(o.CAFile); err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
	}
	c, err := client.New(server, "", client.Options{InsecureDev: o.InsecureDev, CAPEM: caPEM})
	if err != nil {
		return nil, err
	}
	r := collect.Collect(ctx, collect.Options{Software: false})
	resp, err := c.Enroll(ctx, o.Token, client.EnrollDevice{
		Hostname: r.Device.Hostname, OSFamily: r.Device.OSFamily, OSName: r.Device.OSName,
		OSVersion: r.Device.OSVersion, SerialNumber: r.Device.SerialNumber, MachineID: collect.MachineID(ctx),
		AgentVersion: version.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}
	caFile := ""
	if len(caPEM) > 0 {
		// Keep our own protected copy (client.New above already checked it
		// parses and that the server's certificate chains to it).
		if caFile, err = state.SaveCA(p, caPEM); err != nil {
			return nil, fmt.Errorf("saving CA bundle to %s: %w", p.StateDir, err)
		}
	} else if err := os.Remove(p.CAFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	st := &state.State{ServerURL: server, DeviceID: resp.DeviceID, DeviceSecret: resp.DeviceSecret,
		InsecureDev: o.InsecureDev, CAFile: caFile, EnrolledAt: time.Now().UTC(),
		CheckInIntervalSeconds: resp.CheckInIntervalSeconds, CommandPollSeconds: resp.CommandPollSeconds}
	if old, err := state.Load(p); err == nil && old.DeviceID == resp.DeviceID {
		st.ExecutedCommands = old.ExecutedCommands
	}
	if err := state.Save(p, st); err != nil {
		return nil, fmt.Errorf("saving credentials to %s: %w", p.StateFile(), err)
	}
	return resp, nil
}

// Auto-enrollment timing (variables so tests can shorten them).
var (
	// How often an unenrolled service looks for enroll.json.
	ConfigPollInterval = time.Minute
	// Retry delay after the server rejected the installer's token (expired,
	// revoked or used up): slow, the token will not fix itself.
	TokenRejectedRetry = 30 * time.Minute
	// Backoff for transient failures (server unreachable, TLS, 5xx).
	EnrollBackoff = backoff.Policy{Base: 15 * time.Second, Max: 15 * time.Minute, Jitter: 0.1}
)

// DiscardEnrollConfig deletes a pending enroll.json on an already enrolled
// device: re-installing the package never re-enrolls (identity is kept).
func DiscardEnrollConfig(p state.Paths, st *state.State) {
	if _, err := os.Lstat(p.EnrollFile()); err != nil {
		return
	}
	if err := state.RemoveEnrollConfig(p); err != nil {
		slog.Warn("could not delete the installer's enrollment config", "file", p.EnrollFile(), "err", err)
		return
	}
	slog.Info("already enrolled; ignored and deleted the installer's enrollment config "+
		"(use `cnapp-agent enroll` to re-enroll deliberately)", "device_id", st.DeviceID, "server", st.ServerURL)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// AutoEnroll blocks until the device is enrolled: it enrolls with the
// installer-provided enroll.json (retrying with backoff), or notices a manual
// `cnapp-agent enroll`. The token file is deleted once enrollment succeeded.
// It returns only on success or when ctx is cancelled.
func AutoEnroll(ctx context.Context, p state.Paths) error {
	failures := 0
	waitingLogged := false
	for {
		if st, err := state.Load(p); err == nil {
			DiscardEnrollConfig(p, st)
			return nil
		}
		var wait time.Duration
		cfg, err := state.LoadEnrollConfig(p)
		switch {
		case errors.Is(err, state.ErrNoEnrollConfig):
			if !waitingLogged {
				slog.Warn("not enrolled: waiting for an enrollment config from an installer package, "+
					"or run `cnapp-agent enroll`", "config_file", p.EnrollFile())
				waitingLogged = true
			}
			wait = ConfigPollInterval
		case err != nil:
			slog.Error("invalid enrollment config; fix or replace it (re-run the installer)", "file", p.EnrollFile(), "err", err)
			wait = ConfigPollInterval
		default:
			slog.Info("enrolling with the installer's enrollment config", "server", cfg.ServerURL,
				"private_ca", cfg.CAPEM != "")
			resp, err := Enroll(ctx, p, EnrollOptions{Server: cfg.ServerURL, Token: cfg.Token, CAPEM: []byte(cfg.CAPEM)})
			if err == nil {
				verb := "enrolled"
				if resp.Reenrolled {
					verb = "re-enrolled (existing device record kept)"
				}
				if rerr := state.RemoveEnrollConfig(p); rerr != nil {
					slog.Error("enrolled, but could not delete the enrollment config", "file", p.EnrollFile(), "err", rerr)
				}
				slog.Info("device "+verb+"; installer token deleted from disk", "device_id", resp.DeviceID, "server", cfg.ServerURL)
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failures++
			if client.IsUnauthorized(err) {
				wait = TokenRejectedRetry
				slog.Error("enrollment token rejected by the server (expired, revoked or device limit reached): "+
					"download a new installer from Devices > Enroll, or run `cnapp-agent enroll` with a new token",
					"server", cfg.ServerURL, "err", err, "retry_in", wait)
			} else {
				wait = EnrollBackoff.Retry(failures)
				slog.Warn("enrollment failed; retrying", "server", cfg.ServerURL, "err", err, "attempt", failures,
					"retry_in", wait.Round(time.Second))
			}
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return err
		}
	}
}
