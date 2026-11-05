package main

// The Windows Installer package (packaging/windows/msi/cnapp-collector.wxs)
// runs `cnapp-collector msi-install` as its deferred custom action (as SYSTEM,
// after the binary is in place) and `cnapp-collector purge` on uninstall.
//
// msi-install decides everything before it touches the service: the
// enrollment (CNAPP_SERVER / CNAPP_TOKEN / CNAPP_CA_B64 win over the
// pre-configured CNAPP_PRESET; nothing is written on an enrolled host, so
// upgrades, repairs and a take-over of a zip-installed collector keep its
// identity), the service account (GMSA, else the gMSA chosen in the console
// for this download, else what an existing service runs as, else what the
// previous install recorded in service.json, else LocalSystem)
// and the domain-controller rule (a silent first install on a DC needs
// ALLOW_DOMAIN_CONTROLLER=1; the interactive installer asks and sets it).
// Then it (re)creates the CNAPPCollector service exactly like `install` does.

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collector"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/logx"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/service"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
)

// msiInput are the MSI properties handed to the custom action.
type msiInput struct {
	Preset, Server, Token, CAB64, GMSA, AllowDC string
}

// hostInstall is what is already on this host.
type hostInstall struct {
	IsDC           bool
	Enrolled       bool
	Saved          state.ServiceSettings
	HasSaved       bool
	ServiceAccount string // logon account of an existing CNAPPCollector service ("" if none)
}

// installPlan is what msi-install does.
type installPlan struct {
	Enroll      *state.EnrollConfig // nil: keep the current enrollment / nothing given (the service waits)
	RunAs       string              // gMSA; "" = LocalSystem
	RunAsSource string
	DisplayName string
}

const errDCSilent = "this computer is a DOMAIN CONTROLLER: a silent install needs ALLOW_DOMAIN_CONTROLLER=1 " +
	"(we recommend a member server; the collector only reads the directory and runs no commands)"

func isLocalSystem(s string) bool {
	return strings.EqualFold(s, "LocalSystem") || strings.EqualFold(s, `NT AUTHORITY\SYSTEM`) ||
		strings.EqualFold(s, `.\LocalSystem`)
}

// planMSIInstall validates the properties against the host; it changes nothing.
func planMSIInstall(in msiInput, h hostInstall) (*installPlan, error) {
	plan := &installPlan{}
	gmsa := strings.TrimSpace(in.GMSA)
	explicitLocal := isLocalSystem(gmsa)
	if gmsa != "" && !explicitLocal && !collector.ValidGMSA(gmsa) {
		return nil, fmt.Errorf(`GMSA must be a group Managed Service Account such as CORP\svc-collector$ `+
			`(or LocalSystem); got %q`, gmsa)
	}
	allowDC, err := state.ParseBoolSetting(in.AllowDC)
	if err != nil {
		return nil, fmt.Errorf("ALLOW_DOMAIN_CONTROLLER: %w", err)
	}
	var cfg *state.EnrollConfig
	presetRunAs := ""
	switch {
	case strings.TrimSpace(in.Server) != "" || strings.TrimSpace(in.Token) != "":
		cfg = &state.EnrollConfig{ServerURL: strings.TrimSpace(in.Server), Token: strings.TrimSpace(in.Token)}
		if cfg.CAPEM, err = state.DecodeCAB64(in.CAB64); err != nil {
			return nil, fmt.Errorf("CNAPP_CA_B64: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return nil, fmt.Errorf("CNAPP_SERVER / CNAPP_TOKEN: %w", err)
		}
	default:
		raw, err := state.DecodePresetBytes(in.Preset)
		if err != nil {
			return nil, err
		}
		if raw != nil {
			pr, err := collector.ParsePreset(raw)
			if err != nil {
				return nil, fmt.Errorf("pre-configured installer: %w", err)
			}
			cfg = &state.EnrollConfig{Version: 1, ServerURL: pr.ServerURL, Token: pr.Token, CAPEM: pr.CAPEM}
			if err := cfg.Validate(); err != nil {
				return nil, fmt.Errorf("pre-configured installer: %w", err)
			}
			presetRunAs, plan.DisplayName = pr.RunAs, pr.ServiceDisplayName
		}
	}
	if h.IsDC && (allowDC == nil || !*allowDC) && !h.Enrolled && !h.HasSaved {
		return nil, errors.New(errDCSilent)
	}
	switch {
	case explicitLocal:
		plan.RunAsSource = "GMSA=LocalSystem"
	case gmsa != "":
		plan.RunAs, plan.RunAsSource = gmsa, "GMSA property"
	case presetRunAs != "":
		plan.RunAs, plan.RunAsSource = presetRunAs, "installer download"
	case h.ServiceAccount != "":
		// The service still exists (repair, take-over of a zip install, an
		// `sc.exe config` switch): keep what it runs as.
		plan.RunAsSource = "existing service"
		if strings.HasSuffix(h.ServiceAccount, "$") && collector.ValidGMSA(h.ServiceAccount) {
			plan.RunAs = h.ServiceAccount
		}
	case h.HasSaved:
		// An MSI upgrade removed the old product's service first.
		plan.RunAs, plan.RunAsSource = h.Saved.RunAs, "previous install"
	default:
		plan.RunAsSource = "default"
	}
	if plan.DisplayName == "" && h.HasSaved {
		plan.DisplayName = h.Saved.DisplayName
	}
	if !h.Enrolled {
		plan.Enroll = cfg
	}
	return plan, nil
}

func cmdMSIInstall(args []string) error {
	fs, home := flags("msi-install")
	var in msiInput
	fs.StringVar(&in.Preset, "preset", "", "MSI property CNAPP_PRESET")
	fs.StringVar(&in.Server, "server", "", "MSI property CNAPP_SERVER")
	fs.StringVar(&in.Token, "token", "", "MSI property CNAPP_TOKEN")
	fs.StringVar(&in.CAB64, "ca-b64", "", "MSI property CNAPP_CA_B64")
	fs.StringVar(&in.GMSA, "gmsa", "", `MSI property GMSA (DOMAIN\name$ or LocalSystem)`)
	fs.StringVar(&in.AllowDC, "allow-domain-controller", "", "MSI property ALLOW_DOMAIN_CONTROLLER (1)")
	_ = fs.Parse(args)
	p := state.Resolve(*home)
	// Windows Installer does not log a custom action's output: write it to the
	// collector's log, where the troubleshooting guide points (in the protected
	// state folder, secured first on a new host so the log never sits in a readable folder).
	if _, err := os.Stat(p.StateDir); errors.Is(err, os.ErrNotExist) {
		_ = state.SecureDir(p.StateDir)
	}
	if closer, err := logx.Setup(p.LogFile(), true, slog.LevelInfo); err == nil {
		defer closer.Close()
	}
	err := msiInstall(p, *home, in)
	if err != nil {
		slog.Error("MSI install failed", "err", err)
	}
	return err
}

func msiInstall(p state.Paths, home string, in msiInput) error {
	h := hostInstall{IsDC: collector.HostFacts().IsDomainController, ServiceAccount: installedServiceAccount()}
	if _, err := state.Load(p); err == nil {
		h.Enrolled = true
	}
	saved, ok, err := state.LoadServiceSettings(p)
	if err != nil {
		slog.Warn("ignoring the previous service settings", "err", err)
	}
	h.Saved, h.HasSaved = saved, ok
	plan, err := planMSIInstall(in, h)
	if err != nil {
		return err
	}
	if plan.RunAs != "" {
		sid, err := accountSID(plan.RunAs)
		if err != nil {
			return err
		}
		state.ServiceAccountSID = sid
	}
	if plan.Enroll != nil {
		if err := state.SaveEnrollConfig(p, plan.Enroll); err != nil {
			return fmt.Errorf("saving the pending enrollment: %w", err)
		}
	}
	if err := state.SaveServiceSettings(p, state.ServiceSettings{RunAs: plan.RunAs, DisplayName: plan.DisplayName,
		UpdatedAt: time.Now().UTC(), Source: "msi"}); err != nil {
		return fmt.Errorf("saving the service settings: %w", err)
	}
	service.UseCollector(plan.DisplayName)
	if err := service.Install(service.Options{Home: home, RunAs: plan.RunAs}); err != nil {
		return err
	}
	who := "LocalSystem (the computer account)"
	if plan.RunAs != "" {
		who = plan.RunAs
	}
	enrollment := "kept the existing enrollment"
	switch {
	case !h.Enrolled && plan.Enroll != nil:
		enrollment = "enrolls with " + plan.Enroll.ServerURL + " on start"
	case !h.Enrolled:
		enrollment = "not configured (generic MSI without CNAPP_SERVER / CNAPP_TOKEN): the service waits"
	}
	slog.Info("collector installed by the MSI", "service", service.DisplayName, "run_as", who,
		"run_as_source", plan.RunAsSource, "domain_controller", h.IsDC, "enrollment", enrollment)
	fmt.Printf("%s installed and started as %s; %s.\n", service.DisplayName, who, enrollment)
	return nil
}

// cmdPurge deletes the credential, pending enrollment, service settings and
// logs (the MSI runs it on uninstall, after removing the service).
func cmdPurge(args []string) error {
	fs, home := flags("purge")
	_ = fs.Parse(args)
	_, _ = logx.Setup("", true, slog.LevelWarn)
	return purge(state.Resolve(*home))
}

func purge(p state.Paths) error {
	if err := state.Remove(p); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(p.StateDir, update.StateFileName))
	_ = os.RemoveAll(p.LogDir)
	_ = os.Remove(p.StateDir)
	return nil
}
