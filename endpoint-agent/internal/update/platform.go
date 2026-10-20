package update

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/service"
)

// Build-time platform code-signing policy (off by default). Set with
//
//	-ldflags "-X .../internal/update.RequirePlatformSignature=true -X .../internal/update.TrustedPublisher=<value>"
//
// Windows: the new binary must carry a valid Authenticode signature; with
// TrustedPublisher set, the signer certificate subject must contain it
// (e.g. "CN=Contoso Ltd"). macOS: `codesign --verify --strict` must pass and
// the signature must not be ad-hoc; with TrustedPublisher set, the
// TeamIdentifier must equal it. This is in addition to the mandatory Ed25519
// manifest signature, never instead of it.
var (
	RequirePlatformSignature = "false"
	TrustedPublisher         = ""
)

// OSPlatform is the real Platform.
type OSPlatform struct{}

// VerifyBinary implements Platform.
func (OSPlatform) VerifyBinary(path string) error {
	if RequirePlatformSignature != "true" {
		return nil
	}
	return verifyCodeSignature(path, TrustedPublisher)
}

// Preflight implements Platform: the new binary must run and report the signed version.
func (OSPlatform) Preflight(ctx context.Context, path, wantVersion string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	hide(cmd)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("`%s version` failed: %v (%s)", path, err, strings.TrimSpace(truncate(out.String(), 300)))
	}
	if got := strings.TrimSpace(out.String()); got != wantVersion {
		return fmt.Errorf("new binary reports version %q, the signed manifest says %q", truncate(got, 64), wantVersion)
	}
	return nil
}

// StartWatchdog implements Platform.
func (OSPlatform) StartWatchdog(binary string, args []string) error {
	p, err := startDetached(binary, append([]string{"update-watchdog"}, args...))
	if err != nil {
		return err
	}
	return p.Release()
}

// RestartService implements Platform.
func (OSPlatform) RestartService() error { return service.Restart() }
