// Command cnapp-agent is the CNAPP endpoint agent for Windows and macOS.
//
//	cnapp-agent enroll --server https://cnapp.example.com --token cne_...
//	cnapp-agent configure --server URL --token-stdin   # pending enrollment for the service (installers, MDM)
//	cnapp-agent install            # Windows service / macOS LaunchDaemon (elevated)
//	cnapp-agent status
//	cnapp-agent inventory --print  # collect and print JSON, no network
//	cnapp-agent checkin            # one check-in + command poll now
//	cnapp-agent uninstall [--purge]
//	cnapp-agent run                # foreground loop (what the service runs)
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/agent"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/collect"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/logx"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/service"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

const usage = `cnapp-agent %s - CNAPP endpoint agent (inventory, posture, allow-listed remote actions)

Usage:
  cnapp-agent enroll --server URL (--token TOKEN | --token-stdin) [--insecure-dev] [--ca-file PEM]
  cnapp-agent configure --server URL (--token TOKEN | --token-stdin) [--ca-file PEM | --ca-b64 B64]
  cnapp-agent configure --from-file enroll.json   (the MSI also passes --preset)
                                      store a pending enrollment (protected enroll.json); the service
                                      enrolls with it on start, then deletes the token (used by the
                                      MSI / pkg installers and MDM scripts; no-op if already enrolled)
  cnapp-agent install [--wait-for-enrollment]
                                      register and start the OS service (run elevated); without
                                      enrollment or a pending config it needs --wait-for-enrollment
  cnapp-agent uninstall [--purge]     stop and remove the service (--purge also deletes credentials and logs)
  cnapp-agent purge                   delete credentials, pending enrollment and logs (service untouched)
  cnapp-agent status                  show enrollment state (never prints the secret)
  cnapp-agent inventory --print       collect inventory/posture and print JSON (no network)
  cnapp-agent checkin                 run one check-in and command poll now
  cnapp-agent run                     run in the foreground (used by the service)
  cnapp-agent version

--ca-file PEM (or env CNAPP_CA_FILE) trusts a private/internal CA (e.g. an on-prem server's
              CA) in addition to the system store; it is copied next to the credentials.

Common flags: --home DIR  keep state and logs under DIR instead of the system location
              (also CNAPP_AGENT_HOME; for testing)
`

func main() {
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
	case "enroll":
		err = cmdEnroll(args)
	case "configure":
		err = cmdConfigure(args)
	case "purge":
		err = cmdPurge(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "status":
		err = cmdStatus(args)
	case "inventory":
		err = cmdInventory(args)
	case "checkin":
		err = cmdCheckin(args)
	case "run":
		err = cmdRun(args)
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

func quietLogs() { _, _ = logx.Setup("", true, slog.LevelWarn) }

func cmdEnroll(args []string) error {
	fs, home := flags("enroll")
	server := fs.String("server", "", "CNAPP server URL, e.g. https://cnapp.example.com")
	token := fs.String("token", "", "enrollment token (or use --token-stdin / CNAPP_ENROLL_TOKEN)")
	tokenStdin := fs.Bool("token-stdin", false, "read the enrollment token from stdin")
	insecure := fs.Bool("insecure-dev", false, "allow plain http:// (local testing only, never in production)")
	caFile := fs.String("ca-file", os.Getenv("CNAPP_CA_FILE"),
		"PEM CA certificate(s) of a private/internal CA to trust in addition to the system store "+
			"(env CNAPP_CA_FILE); a copy is kept with the agent's credentials")
	_ = fs.Parse(args)
	quietLogs()
	tok, err := readToken(*token, *tokenStdin)
	if err != nil {
		return err
	}
	if *server == "" || tok == "" {
		return errors.New("--server and an enrollment token are required")
	}
	if *insecure {
		fmt.Fprintln(os.Stderr, "WARNING: --insecure-dev allows unencrypted http; use only for local testing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	p := state.Resolve(*home)
	resp, err := agent.Enroll(ctx, p, agent.EnrollOptions{Server: *server, Token: tok, InsecureDev: *insecure, CAFile: *caFile})
	if err != nil {
		return err
	}
	verb := "Enrolled"
	if resp.Reenrolled {
		verb = "Re-enrolled"
	}
	fmt.Printf("%s as device %s. Credentials saved to %s\n", verb, resp.DeviceID, p.StateFile())
	fmt.Println("Next: run `cnapp-agent install` (elevated) to start the service, or `cnapp-agent checkin` to report now.")
	return nil
}

func readToken(token string, fromStdin bool) (string, error) {
	tok := token
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		tok = line
	}
	if tok == "" {
		tok = os.Getenv("CNAPP_ENROLL_TOKEN")
	}
	return strings.TrimSpace(tok), nil
}

// cmdConfigure stores a pending enrollment for the service (installers, MDM).
func cmdConfigure(args []string) error {
	fs, home := flags("configure")
	server := fs.String("server", "", "CNAPP server URL (https://...)")
	token := fs.String("token", "", "enrollment token (or --token-stdin / CNAPP_ENROLL_TOKEN)")
	tokenStdin := fs.Bool("token-stdin", false, "read the enrollment token from stdin")
	caFile := fs.String("ca-file", "", "PEM CA certificate(s) of a private CA (optional)")
	caB64 := fs.String("ca-b64", "", "base64 of the PEM (or DER) CA certificate (optional; MSI property CNAPP_CA_B64)")
	fromFile := fs.String("from-file", "", "read server, token and CA from an enroll.json document")
	preset := fs.String("preset", "", "MSI property CNAPP_PRESET (set by a pre-configured download; used by the MSI)")
	_ = fs.Parse(args)
	quietLogs()
	p := state.Resolve(*home)
	var cfg *state.EnrollConfig
	tok, err := readToken(*token, *tokenStdin)
	if err != nil {
		return err
	}
	// The MSI passes every source; explicit CNAPP_SERVER/CNAPP_TOKEN properties win over
	// the preset, and with neither (generic MSI, no properties) there is nothing to do.
	msiMode := isFlagSet(fs, "preset")
	if msiMode && *fromFile == "" && tok == "" {
		if cfg, err = state.DecodePreset(*preset); err != nil {
			return err
		}
		if cfg == nil {
			fmt.Println("No enrollment configuration given (generic MSI without CNAPP_SERVER/CNAPP_TOKEN): " +
				"the service waits for `cnapp-agent configure` or `cnapp-agent enroll`.")
			return nil
		}
	} else if *fromFile != "" {
		b, err := os.ReadFile(*fromFile)
		if err != nil {
			return err
		}
		if cfg, err = state.ParseEnrollConfig(b); err != nil {
			return fmt.Errorf("%s: %w", *fromFile, err)
		}
	} else {
		cfg = &state.EnrollConfig{ServerURL: *server, Token: tok}
		switch {
		case *caFile != "":
			b, err := os.ReadFile(*caFile)
			if err != nil {
				return fmt.Errorf("reading CA file: %w", err)
			}
			cfg.CAPEM = string(b)
		case strings.TrimSpace(*caB64) != "":
			if cfg.CAPEM, err = state.DecodeCAB64(*caB64); err != nil {
				return err
			}
		}
	}
	if st, err := state.Load(p); err == nil {
		fmt.Printf("Already enrolled as device %s with %s: enrollment config not written "+
			"(use `cnapp-agent enroll` to re-enroll).\n", st.DeviceID, st.ServerURL)
		return nil
	}
	if err := state.SaveEnrollConfig(p, cfg); err != nil {
		return err
	}
	fmt.Printf("Enrollment config for %s saved to %s; the service enrolls with it on start.\n", cfg.ServerURL, p.EnrollFile())
	return nil
}

func isFlagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

func purge(p state.Paths) error {
	if err := state.Remove(p); err != nil {
		return err
	}
	_ = os.RemoveAll(p.LogDir)
	_ = os.Remove(p.StateDir)
	return nil
}

func cmdPurge(args []string) error {
	fs, home := flags("purge")
	_ = fs.Parse(args)
	quietLogs()
	if err := purge(state.Resolve(*home)); err != nil {
		return err
	}
	fmt.Println("Credentials, pending enrollment and logs deleted.")
	return nil
}

func cmdInstall(args []string) error {
	fs, home := flags("install")
	wait := fs.Bool("wait-for-enrollment", false,
		"install even if not enrolled and no enrollment config is present (the service waits for one)")
	_ = fs.Parse(args)
	quietLogs()
	p := state.Resolve(*home)
	if _, err := state.Load(p); err != nil {
		if _, cerr := state.LoadEnrollConfig(p); cerr != nil && !*wait {
			return fmt.Errorf("%w; enroll (or `cnapp-agent configure`) before installing the service, "+
				"or pass --wait-for-enrollment", err)
		}
	}
	if err := service.Install(service.Options{Home: *home}); err != nil {
		return err
	}
	fmt.Println("Service installed and started.")
	return nil
}

func cmdUninstall(args []string) error {
	fs, home := flags("uninstall")
	purgeAll := fs.Bool("purge", false, "also delete the device credential and agent logs")
	_ = fs.Parse(args)
	quietLogs()
	if err := service.Uninstall(); err != nil {
		return err
	}
	if *purgeAll {
		if err := purge(state.Resolve(*home)); err != nil {
			return err
		}
		fmt.Println("Service removed; credentials and logs deleted. Revoke or delete the device in the CNAPP console as well.")
		return nil
	}
	fmt.Println("Service removed. The device credential was kept (use --purge to delete it).")
	return nil
}

func cmdStatus(args []string) error {
	fs, home := flags("status")
	_ = fs.Parse(args)
	p := state.Resolve(*home)
	st, err := state.Load(p)
	if errors.Is(err, state.ErrNotEnrolled) {
		cfg, cerr := state.LoadEnrollConfig(p)
		if cerr != nil {
			return err
		}
		out := map[string]any{"agent_version": version.Version, "enrolled": false, "log_file": p.LogFile(),
			"pending_enrollment": map[string]any{"server_url": cfg.ServerURL, "config_file": p.EnrollFile(),
				"private_ca": cfg.CAPEM != ""}}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return nil
	}
	if err != nil {
		return err
	}
	out := map[string]any{"enrolled": true, "agent_version": version.Version, "state_file": p.StateFile(), "log_file": p.LogFile(),
		"state": st.Redacted()}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdInventory(args []string) error {
	fs, _ := flags("inventory")
	print := fs.Bool("print", false, "print the collected JSON report to stdout")
	noSoftware := fs.Bool("no-software", false, "skip the installed-software list")
	_ = fs.Parse(args)
	quietLogs()
	if !*print {
		return errors.New("use --print (inventory never sends anything)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r := collect.Collect(ctx, collect.Options{Software: !*noSoftware})
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// enrolledAgent waits for (auto-)enrollment if needed, then loads the agent.
func enrolledAgent(ctx context.Context, home string) (*agent.Agent, error) {
	p := state.Resolve(home)
	if !p.Custom {
		// Re-assert the protected ACL / mode of the system state directory.
		if err := state.SecureDir(p.StateDir); err != nil {
			slog.Warn("could not secure the state directory", "dir", p.StateDir, "err", err)
		}
	}
	st, err := state.Load(p)
	switch {
	case err == nil:
		agent.DiscardEnrollConfig(p, st)
	case errors.Is(err, state.ErrNotEnrolled):
		if err := agent.AutoEnroll(ctx, p); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return load(home)
}

func load(home string) (*agent.Agent, error) {
	a, err := agent.Load(state.Resolve(home))
	if err != nil {
		return nil, err
	}
	a.Restart = func() {
		slog.Info("restart requested; exiting so the service manager restarts the agent")
		os.Exit(3)
	}
	return a, nil
}

func cmdCheckin(args []string) error {
	fs, home := flags("checkin")
	_ = fs.Parse(args)
	// Log to the agent log as well (so collect_logs bundles include manual runs); console only if not writable.
	if closer, err := logx.Setup(state.Resolve(*home).LogFile(), true, slog.LevelInfo); err == nil {
		defer closer.Close()
	} else {
		_, _ = logx.Setup("", true, slog.LevelInfo)
	}
	a, err := load(*home)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if err := a.CheckIn(ctx); err != nil {
		return fmt.Errorf("check-in: %w", err)
	}
	if err := a.PollCommands(ctx); err != nil {
		return fmt.Errorf("command poll: %w", err)
	}
	fmt.Println("Check-in and command poll completed.")
	return nil
}

func runLoop(home string, console bool) error {
	p := state.Resolve(home)
	closer, err := logx.Setup(p.LogFile(), console, slog.LevelInfo)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	defer closer.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := enrolledAgent(ctx, home)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		slog.Error("cannot start", "err", err)
		return err
	}
	return a.Run(ctx)
}

func cmdRun(args []string) error {
	fs, home := flags("run")
	_ = fs.Parse(args)
	return runLoop(*home, true)
}

// runService is the Windows service entry point (args come from the service config).
func runService() int {
	home := ""
	for i, a := range os.Args {
		if a == "--home" && i+1 < len(os.Args) {
			home = os.Args[i+1]
		}
	}
	err := service.RunService(func(ctx context.Context) error {
		p := state.Resolve(home)
		closer, err := logx.Setup(p.LogFile(), false, slog.LevelInfo)
		if err != nil {
			return err
		}
		defer closer.Close()
		a, err := enrolledAgent(ctx, home)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Error("cannot start", "err", err)
			return err
		}
		return a.Run(ctx)
	})
	if err != nil {
		return 1
	}
	return 0
}
