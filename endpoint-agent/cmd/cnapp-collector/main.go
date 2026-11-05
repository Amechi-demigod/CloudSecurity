// Command cnapp-collector is the dedicated directory collector (Windows): it
// reads Active Directory for the CNAPP server's directory discovery and does
// nothing else. It is a separate program from the endpoint agent, with its own
// enrollment, credential, service and API; its command set is limited to
// directory work (internal/collector.AllowedCommands).
//
//	cnapp-collector install --preset collector.json [--run-as DOMAIN\gmsa$]
//	cnapp-collector status
//	cnapp-collector diagnose --domain corp.example.com [--security sealed|ldaps|starttls]
//	cnapp-collector uninstall [--purge]
//	cnapp-collector run                # foreground loop (what the service runs)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/backoff"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collector"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/directory"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/logx"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/service"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

const usage = `cnapp-collector %s - directory collector (read-only Active Directory discovery)

Usage:
  cnapp-collector install --preset collector.json [--run-as DOMAIN\name$] [--allow-domain-controller]
                                   install / upgrade the service (elevated); --run-as: a gMSA
  cnapp-collector uninstall [--purge]   remove the service (--purge: also credentials and logs)
  cnapp-collector status                enrollment and identity (never prints the secret)
  cnapp-collector diagnose --domain D [--security sealed|ldaps|starttls] [--server DC]
                                   run the console's Test checks locally, as the current identity
  cnapp-collector run                   run in the foreground (used by the service)
  cnapp-collector version | update-keys

The collector runs no scripts, remote sessions or device actions: it only reads the
directory and uploads what it read. Self-update installs only releases signed by a
key compiled into this binary.
`

func main() {
	service.UseCollector("")
	state.ProductDir = "CNAPP Collector"
	update.Product = "cnapp-collector"
	directory.SealedEnabled = true
	setServiceAccountSID()
	if service.IsService() {
		os.Exit(runService())
	}
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version.Version)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "status":
		err = cmdStatus(args)
	case "diagnose":
		err = cmdDiagnose(args)
	case "run":
		err = cmdRun(args)
	case "update-watchdog": // started detached by the service during a self-update
		err = cmdUpdateWatchdog(args)
	case "update-keys":
		var keys []update.TrustedKey
		if keys, err = update.BuiltinKeys(); err == nil {
			for _, k := range keys {
				fmt.Println(k.ID)
			}
		}
	case "version", "--version", "-v":
		fmt.Println(version.Version)
	case "help", "--help", "-h":
		fmt.Printf(usage, version.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, version.Version)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	home := fs.String("home", "", "directory for state and logs (testing; default: system location)")
	return fs, home
}

const dcWarning = "WARNING: this host is a DOMAIN CONTROLLER. Domain controllers are your most sensitive servers; " +
	"we recommend a member server. This collector cannot run commands, scripts or remote sessions (it only reads " +
	"the directory), so installing it here is allowed."

func cmdInstall(args []string) error {
	fs, home := flags("install")
	presetFile := fs.String("preset", "", "collector.json from the console's installer")
	runAs := fs.String("run-as", "", `group Managed Service Account to run as (DOMAIN\name$); default LocalSystem`)
	allowDC := fs.Bool("allow-domain-controller", false, "install on a domain controller without asking")
	_ = fs.Parse(args)
	_, _ = logx.Setup("", true, slog.LevelWarn)
	if *presetFile == "" {
		return errors.New("--preset collector.json is required (download it from Connectors & scans > Collectors)")
	}
	b, err := os.ReadFile(*presetFile)
	if err != nil {
		return err
	}
	pr, err := collector.ParsePreset(b)
	if err != nil {
		return err
	}
	if *runAs == "" {
		*runAs = pr.RunAs
	}
	if *runAs != "" && !strings.HasSuffix(*runAs, "$") {
		return errors.New("--run-as must be a group Managed Service Account (DOMAIN\\name$); for a service account " +
			"with a password use the source's service-account option instead")
	}
	if collector.HostFacts().IsDomainController {
		fmt.Fprintln(os.Stderr, dcWarning)
		if !*allowDC && !confirm("Install on this domain controller anyway? (yes/no) ") {
			return errors.New("cancelled")
		}
	}
	service.UseCollector(pr.ServiceDisplayName)
	if *runAs != "" {
		sid, err := accountSID(*runAs)
		if err != nil {
			return err
		}
		state.ServiceAccountSID = sid
	}
	p := state.Resolve(*home)
	if err := state.SaveEnrollConfig(p, &state.EnrollConfig{Version: 1, ServerURL: pr.ServerURL, Token: pr.Token,
		CAPEM: pr.CAPEM}); err != nil {
		return fmt.Errorf("saving the pending enrollment: %w", err)
	}
	if err := service.Install(service.Options{Home: *home, RunAs: *runAs}); err != nil {
		return err
	}
	who := "LocalSystem (the computer account)"
	if *runAs != "" {
		who = *runAs
	}
	fmt.Printf("%s installed and started as %s; it enrolls with %s within a minute.\n", service.DisplayName, who,
		pr.ServerURL)
	return nil
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	var s string
	_, _ = fmt.Scanln(&s)
	return strings.EqualFold(strings.TrimSpace(s), "yes")
}

func cmdUninstall(args []string) error {
	fs, home := flags("uninstall")
	purge := fs.Bool("purge", false, "also delete the collector credential and logs")
	_ = fs.Parse(args)
	_, _ = logx.Setup("", true, slog.LevelWarn)
	if err := service.Uninstall(); err != nil {
		return err
	}
	if *purge {
		p := state.Resolve(*home)
		_ = state.RemoveEnrollConfig(p)
		if err := state.Remove(p); err != nil {
			return err
		}
		_ = os.RemoveAll(p.LogDir)
		_ = os.Remove(p.StateDir)
		fmt.Println("Collector removed with its credential and logs. Revoke and delete it in the console as well.")
		return nil
	}
	fmt.Println("Collector service removed (credential kept; use --purge to delete it).")
	return nil
}

func cmdStatus(args []string) error {
	fs, home := flags("status")
	_ = fs.Parse(args)
	p := state.Resolve(*home)
	f := collector.HostFacts()
	out := map[string]any{"version": version.Version, "host": f.Hostname, "domain": f.Domain, "run_as": f.RunAs,
		"run_as_kind": f.RunAsKind, "is_domain_controller": f.IsDomainController, "log_file": p.LogFile()}
	if st, err := state.Load(p); err == nil {
		out["enrolled"], out["collector_id"], out["server"] = true, st.DeviceID, st.ServerURL
	} else {
		out["enrolled"] = false
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdDiagnose(args []string) error {
	fs := flag.NewFlagSet("diagnose", flag.ExitOnError)
	domain := fs.String("domain", "", "AD domain (default: this computer's)")
	security := fs.String("security", "sealed", "sealed | ldaps | starttls")
	server := fs.String("server", "", "a domain controller (default: DC locator)")
	_ = fs.Parse(args)
	f := collector.HostFacts()
	if *domain == "" {
		*domain = f.Domain
	}
	raw := map[string]any{"domain": *domain, "security": *security, "auth": "kerberos"}
	if *server != "" {
		raw["servers"] = []any{*server}
	}
	p, err := directory.ParseDiagParams(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	res := directory.DefaultDiagnostics(f.RunAs).Run(ctx, p)
	for _, s := range res.Steps {
		fmt.Printf("%-5s %-38s %s\n", strings.ToUpper(s.Status), s.Label, s.Detail)
	}
	if !res.OK() {
		return errors.New("one or more checks failed")
	}
	return nil
}

func cmdRun(args []string) error {
	fs, home := flags("run")
	_ = fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	closer, err := logx.Setup(state.Resolve(*home).LogFile(), true, slog.LevelInfo)
	if err == nil {
		defer closer.Close()
	}
	return run(ctx, *home, false)
}

func runService() int {
	home := ""
	for i, a := range os.Args {
		if a == "--home" && i+1 < len(os.Args) {
			home = os.Args[i+1]
		}
	}
	err := service.RunService(func(ctx context.Context) error {
		closer, err := logx.Setup(state.Resolve(home).LogFile(), false, slog.LevelInfo)
		if err != nil {
			return err
		}
		defer closer.Close()
		return run(ctx, home, true)
	})
	if err != nil {
		return 1
	}
	return 0
}

// run enrolls (pending enroll.json from the installer) and runs the loop.
func run(ctx context.Context, home string, asService bool) error {
	p := state.Resolve(home)
	pol := backoff.Policy{Base: 15 * time.Second, Max: 15 * time.Minute, Jitter: 0.1}
	for attempt := 1; ; attempt++ {
		if _, err := state.Load(p); err == nil {
			break
		}
		cfg, err := state.LoadEnrollConfig(p)
		if err == nil {
			err = collector.Enroll(ctx, p, cfg, collector.HostFacts(), collector.HashMachineID(machineGUID()),
				runtime.GOOS, runtime.GOARCH)
			if err == nil {
				slog.Info("collector enrolled", "server", cfg.ServerURL)
				break
			}
		}
		slog.Warn("not enrolled yet", "err", err)
		t := time.NewTimer(pol.Retry(attempt))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
	st, err := state.Load(p)
	if err != nil {
		return err
	}
	api, err := collector.NewClient(st.ServerURL, st.DeviceSecret, nil, st.CAFile, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	c := &collector.Collector{API: api, Paths: p, ID: st.DeviceID, Facts: collector.HostFacts,
		Restart: func() { os.Exit(3) }}
	if asService && service.ManagedByServiceManager() {
		if u, err := newUpdater(home, api); err != nil {
			slog.Error("self-update disabled", "err", err)
		} else {
			if u.OnStart() {
				os.Exit(3)
			}
			if len(u.Keys) > 0 {
				c.Updater = u
			}
		}
	}
	slog.Info("collector started", "collector_id", st.DeviceID, "server", st.ServerURL, "version", version.Version)
	return c.Run(ctx)
}

func newUpdater(home string, t update.Transport) (*update.Updater, error) {
	keys, err := update.BuiltinKeys()
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	var wargs []string
	if home != "" {
		wargs = []string{"--home", home}
	}
	return &update.Updater{Keys: keys, Current: version.Version, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		BinaryPath: exe, Paths: state.Resolve(home), Transport: t, Platform: update.OSPlatform{},
		WatchdogArgs: wargs}, nil
}

func cmdUpdateWatchdog(args []string) error {
	fs, home := flags("update-watchdog")
	_ = fs.Parse(args)
	p := state.Resolve(*home)
	if closer, err := logx.Setup(p.LogFile(), false, slog.LevelInfo); err == nil {
		defer closer.Close()
	}
	u := &update.Updater{Current: version.Version, Paths: p, Platform: update.OSPlatform{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	return u.Watchdog(ctx, 2*time.Second)
}
