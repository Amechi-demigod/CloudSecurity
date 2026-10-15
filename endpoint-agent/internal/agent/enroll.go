package agent

import (
	"context"
	"fmt"
	"time"

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
	CAFile      string
}

// Enroll exchanges an enrollment token for a device credential and stores it.
// Running it again re-enrolls (the server rotates the credential).
func Enroll(ctx context.Context, p state.Paths, o EnrollOptions) (*client.EnrollResponse, error) {
	server, err := state.ValidateServerURL(o.Server, o.InsecureDev)
	if err != nil {
		return nil, err
	}
	c, err := client.New(server, "", client.Options{InsecureDev: o.InsecureDev, CAFile: o.CAFile})
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
	st := &state.State{ServerURL: server, DeviceID: resp.DeviceID, DeviceSecret: resp.DeviceSecret,
		InsecureDev: o.InsecureDev, CAFile: o.CAFile, EnrolledAt: time.Now().UTC(),
		CheckInIntervalSeconds: resp.CheckInIntervalSeconds, CommandPollSeconds: resp.CommandPollSeconds}
	if old, err := state.Load(p); err == nil && old.DeviceID == resp.DeviceID {
		st.ExecutedCommands = old.ExecutedCommands
	}
	if err := state.Save(p, st); err != nil {
		return nil, fmt.Errorf("saving credentials to %s: %w", p.StateFile(), err)
	}
	return resp, nil
}
