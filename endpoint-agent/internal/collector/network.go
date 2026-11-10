package collector

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/netscan"
)

// Network discovery commands (internal/netscan). The scan parameters carry
// SNMP secrets: they are parsed once, never logged (Params / Credential log
// redacted), and every error text is redacted before it is reported.

// prepareScan validates the command and claims the single scan slot. On
// success the caller must call runScan (which releases the slot). A non-nil
// Outcome (with a nil Params) is the rejection / busy answer.
func (c *Collector) prepareScan(cmd model.Command) (*netscan.Params, string, Outcome) {
	p, err := netscan.ParseParams(cmd.Params)
	if err != nil {
		return nil, "", Outcome{Status: "rejected", Output: err.Error()}
	}
	host := ""
	if h, ok := c.API.(interface{ Host() string }); ok {
		host = h.Host()
	}
	path, err := netscan.UploadPath(p.UploadURL, host)
	if err != nil {
		return nil, "", Outcome{Status: "rejected", Output: err.Error()}
	}
	if !c.scanBusy.CompareAndSwap(false, true) {
		return nil, "", Outcome{Status: "failed", Output: "a network scan is already running on this collector"}
	}
	return p, path, Outcome{}
}

// scanDeadline: the scan ends at the command's deadline (expires_at, in server
// time) and never runs longer than maxScanDuration.
func (c *Collector) scanDeadline(cmd model.Command) time.Time {
	d := time.Now().Add(maxScanDuration)
	if !cmd.ExpiresAt.IsZero() {
		c.mu.Lock()
		skew := c.skew
		c.mu.Unlock()
		if e := cmd.ExpiresAt.Add(-skew); e.Before(d) {
			d = e
		}
	}
	return d
}

// runScan performs a prepared scan (the slot is released when it returns).
func (c *Collector) runScan(ctx context.Context, cmd model.Command, p *netscan.Params, path string) Outcome {
	defer c.scanBusy.Store(false)
	ctx, cancel := context.WithDeadline(ctx, c.scanDeadline(cmd))
	defer cancel()
	env := netscan.DefaultEnv()
	if c.NetEnv != nil {
		env = c.NetEnv()
	}
	slog.Info("network scan started", "command_id", cmd.ID, "scan", p)
	res := env.Run(ctx, p, path, c.API)
	out := fmt.Sprintf("scan %s: %d addresses, %d alive, %d with SNMP, %d batches", res.ScanID, res.Addresses, res.Alive,
		res.SNMP, res.Batches)
	o := Outcome{Status: "succeeded", Output: out, ResultData: res}
	if res.Failed {
		o.Status = "failed"
		o.Output = out + "; results could not be delivered to the server"
	}
	return o
}

// startScan validates synchronously (so a rejection or "busy" answer is
// immediate) and runs the scan in the background.
func (c *Collector) startScan(ctx context.Context, cmd model.Command) {
	p, path, o := c.prepareScan(cmd)
	if p == nil {
		c.report(ctx, cmd, o)
		return
	}
	c.mu.Lock()
	base := c.baseCtx
	c.mu.Unlock()
	if base == nil {
		base = ctx
	}
	c.scanWG.Add(1)
	go func() {
		defer c.scanWG.Done()
		o := c.runScan(base, cmd, p, path)
		// The service may be stopping: still report, with its own deadline.
		rctx, cancel := context.WithTimeout(context.WithoutCancel(base), 30*time.Second)
		defer cancel()
		c.report(rctx, cmd, o)
	}()
}

// networkSubnets suggests subnets from AD Sites and the DHCP servers
// authorised in AD (read-only).
func (c *Collector) networkSubnets(ctx context.Context) Outcome {
	mk := c.SubnetEnv
	if mk == nil {
		mk = netscan.DefaultSubnetEnv
	}
	env, err := mk(c.Facts().Domain)
	if err != nil {
		return Outcome{Status: "failed", Output: err.Error()}
	}
	res, err := netscan.Subnets(ctx, env)
	if err != nil {
		return Outcome{Status: "failed", Output: err.Error()}
	}
	return Outcome{Status: "succeeded", ResultData: res,
		Output: fmt.Sprintf("%d AD subnets, %d DHCP scopes, %d errors", len(res.ADSites), len(res.DHCPScopes), len(res.Errors))}
}
