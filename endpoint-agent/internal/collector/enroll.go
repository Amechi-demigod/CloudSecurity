package collector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/client"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

// Preset is collector.json from the console's pre-configured installer.
type Preset struct {
	Version            int    `json:"version"`
	Kind               string `json:"kind"`
	ServerURL          string `json:"server_url"`
	Token              string `json:"token"`
	CAPEM              string `json:"ca_pem,omitempty"`
	Name               string `json:"name,omitempty"`
	ServiceDisplayName string `json:"service_display_name,omitempty"`
	RunAs              string `json:"run_as,omitempty"`
}

// ParsePreset validates collector.json.
func ParsePreset(b []byte) (*Preset, error) {
	var p Preset
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("collector.json: %w", err)
	}
	if p.Version != 1 || p.Kind != "collector" {
		return nil, errors.New("collector.json is not a version 1 collector preset")
	}
	if !strings.HasPrefix(p.Token, "cnct_") || len(p.Token) > 128 {
		return nil, errors.New("collector.json has no collector enrollment token")
	}
	if _, err := state.ValidateServerURL(p.ServerURL, false); err != nil {
		return nil, err
	}
	if len(p.ServiceDisplayName) > 80 || strings.ContainsAny(p.ServiceDisplayName, "\r\n\x00") {
		return nil, errors.New("collector.json: invalid service_display_name")
	}
	if p.RunAs != "" && !ValidGMSA(p.RunAs) {
		return nil, errors.New(`collector.json: run_as must be a gMSA like CORP\svc-collector$`)
	}
	return &p, nil
}

// UserAgent identifies the collector to the server (update offers use it).
func UserAgent(goos, goarch string) string {
	return fmt.Sprintf("cnapp-collector/%s (%s; %s)", version.Version, goos, goarch)
}

// HashMachineID mirrors the agent's machine id hash with its own context.
func HashMachineID(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("cnapp-collector:" + raw))
	return hex.EncodeToString(sum[:])
}

// NewClient builds the /api/collector client.
func NewClient(serverURL, secret string, caPEM []byte, caFile, goos, goarch string) (*client.Client, error) {
	return client.New(serverURL, secret, client.Options{CAPEM: caPEM, CAFile: caFile, APIPrefix: "/api/collector",
		UserAgent: UserAgent(goos, goarch), Features: Features})
}

// Enroll exchanges the pending enroll.json token for the collector credential.
func Enroll(ctx context.Context, p state.Paths, cfg *state.EnrollConfig, facts Facts, machineID, goos, goarch string) error {
	c, err := NewClient(cfg.ServerURL, "", []byte(cfg.CAPEM), "", goos, goarch)
	if err != nil {
		return err
	}
	var resp struct {
		CollectorID     string `json:"collector_id"`
		CollectorSecret string `json:"collector_secret"`
	}
	if err := c.PostJSON(ctx, "/api/collector/enroll", map[string]any{"token": cfg.Token, "machine_id": machineID,
		"facts": facts}, &resp); err != nil {
		return fmt.Errorf("collector enrollment failed: %w", err)
	}
	caFile := ""
	if cfg.CAPEM != "" {
		if caFile, err = state.SaveCA(p, []byte(cfg.CAPEM)); err != nil {
			return err
		}
	}
	st := &state.State{ServerURL: cfg.ServerURL, DeviceID: resp.CollectorID, DeviceSecret: resp.CollectorSecret,
		CAFile: caFile, EnrolledAt: time.Now().UTC(), CommandPollSeconds: 60}
	if err := state.Save(p, st); err != nil {
		return err
	}
	if err := state.RemoveEnrollConfig(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
