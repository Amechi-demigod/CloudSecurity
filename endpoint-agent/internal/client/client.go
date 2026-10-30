// Package client talks to the CNAPP server's /api/agent/* endpoints.
//
// The agent only makes outbound HTTPS requests (pull model); it never listens
// on a port. Plain http is refused unless the agent was enrolled with
// --insecure-dev. Redirects are never followed, so the device credential can
// only ever be sent to the enrolled server.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/model"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/state"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/update"
	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

const maxResponse = 1 << 20

// HTTPError is a non-2xx response.
type HTTPError struct {
	Status int
	Detail string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("server returned %d: %s", e.Status, e.Detail) }

// IsUnauthorized reports a rejected or superseded credential (401) or a revoked device (403).
func IsUnauthorized(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && (he.Status == http.StatusUnauthorized || he.Status == http.StatusForbidden)
}

// Client is an agent API client.
type Client struct {
	base   string
	secret string
	http   *http.Client
	dl     *http.Client // no overall timeout (large downloads); bounded by the context
	// pinned trusts ONLY the enrollment CA (nil: system roots); used for the
	// remote-session relay socket.
	pinned      *tls.Config
	insecureDev bool
}

// Options configure transport security.
type Options struct {
	InsecureDev bool   // allow http:// (local testing only)
	CAFile      string // extra PEM CA bundle (private PKI); system roots are always trusted
	CAPEM       []byte // same, in memory (used instead of CAFile when set)
	Timeout     time.Duration
}

// New builds a client for serverURL authenticating with the device secret (may be empty for Enroll).
func New(serverURL, secret string, o Options) (*Client, error) {
	base, err := state.ValidateServerURL(serverURL, o.InsecureDev)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	var pinned *tls.Config
	if o.CAFile != "" || len(o.CAPEM) > 0 {
		pem := o.CAPEM
		if len(pem) == 0 {
			if pem, err = os.ReadFile(o.CAFile); err != nil {
				return nil, fmt.Errorf("reading CA file: %w", err)
			}
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no PEM certificates")
		}
		tlsCfg.RootCAs = pool
		only := x509.NewCertPool()
		only.AppendCertsFromPEM(pem)
		pinned = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: only}
	}
	if o.Timeout == 0 {
		o.Timeout = 60 * time.Second
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	noRedirect := func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") }
	return &Client{base: base, secret: secret,
		http:   &http.Client{Transport: tr, Timeout: o.Timeout, CheckRedirect: noRedirect},
		dl:     &http.Client{Transport: tr, CheckRedirect: noRedirect},
		pinned: pinned, insecureDev: o.InsecureDev,
	}, nil
}

// RelayConfig is what the remote-session dialer needs: the enrolled server
// URL, the device credential and a TLS config that trusts only the enrollment
// CA when there is one (system roots otherwise).
func (c *Client) RelayConfig() (base, secret string, pinned *tls.Config, insecureDev bool) {
	if c.pinned != nil {
		pinned = c.pinned.Clone()
	}
	return c.base, c.secret, pinned, c.insecureDev
}

func (c *Client) do(ctx context.Context, method, path, contentType string, body []byte, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("X-CNAPP-Agent-Features", version.Features)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		detail := strings.TrimSpace(string(data))
		var e struct {
			Detail any `json:"detail"`
		}
		if json.Unmarshal(data, &e) == nil && e.Detail != nil {
			if s, ok := e.Detail.(string); ok {
				detail = s
			} else if b, err := json.Marshal(e.Detail); err == nil {
				detail = string(b)
			}
		}
		if len(detail) > 2000 {
			detail = detail[:2000]
		}
		return &HTTPError{Status: resp.StatusCode, Detail: detail}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (c *Client) postJSON(ctx context.Context, path string, in, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, "application/json", b, nil, out)
}

// EnrollDevice identifies the machine at enrollment.
type EnrollDevice struct {
	Hostname     string `json:"hostname"`
	OSFamily     string `json:"os_family"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	SerialNumber string `json:"serial_number"`
	MachineID    string `json:"machine_id"`
	AgentVersion string `json:"agent_version"`
}

// EnrollResponse carries the per-device credential.
type EnrollResponse struct {
	DeviceID               string    `json:"device_id"`
	DeviceSecret           string    `json:"device_secret"`
	CheckInIntervalSeconds int       `json:"check_in_interval_seconds"`
	CommandPollSeconds     int       `json:"command_poll_seconds"`
	ServerTime             time.Time `json:"server_time"`
	Reenrolled             bool      `json:"reenrolled"`
}

// Enroll exchanges an enrollment token for a device credential.
func (c *Client) Enroll(ctx context.Context, token string, d EnrollDevice) (*EnrollResponse, error) {
	var out EnrollResponse
	err := c.postJSON(ctx, "/api/agent/enroll", map[string]any{"token": token, "device": d}, &out)
	if err != nil {
		return nil, err
	}
	if out.DeviceID == "" || out.DeviceSecret == "" {
		return nil, errors.New("server returned an incomplete enrollment response")
	}
	return &out, nil
}

// CheckinResponse is returned by CheckIn.
type CheckinResponse struct {
	DeviceID        string    `json:"device_id"`
	ServerTime      time.Time `json:"server_time"`
	PendingCommands int       `json:"pending_commands"`
	Issues          []string  `json:"issues"`
	// Update is set when the server wants this device to run another
	// (signed) agent release; older servers omit it.
	Update *update.Offer `json:"update,omitempty"`
}

// CheckIn sends a full inventory/posture report.
func (c *Client) CheckIn(ctx context.Context, r *model.Report) (*CheckinResponse, error) {
	r.Normalize()
	var out CheckinResponse
	if err := c.postJSON(ctx, "/api/agent/checkin", r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Commands fetches (and thereby receives exactly once) pending commands.
func (c *Client) Commands(ctx context.Context) (*model.CommandList, error) {
	var out model.CommandList
	if err := c.do(ctx, http.MethodGet, "/api/agent/commands", "", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Result reports a command's outcome.
func (c *Client) Result(ctx context.Context, cmd model.Command, status, output string) error {
	return c.ResultFull(ctx, cmd, status, output, nil, nil)
}

// ResultWithExit reports a command's outcome with a script exit code.
func (c *Client) ResultWithExit(ctx context.Context, cmd model.Command, status, output string, exitCode *int) error {
	return c.ResultFull(ctx, cmd, status, output, exitCode, nil)
}

// ResultFull reports a command's outcome with an optional script exit code
// and/or result_data (isolate_host/restore_host pre-flight findings and
// crash-recovery outcomes - see commands.Outcome.ResultData, strictly
// validated server-side against schemas_devices.IsolateHostResultData /
// RestoreHostResultData). Both are left out of the request body entirely
// when nil/empty, not sent as null/{}.
func (c *Client) ResultFull(ctx context.Context, cmd model.Command, status, output string, exitCode *int,
	resultData map[string]any) error {
	if len(output) > 16000 {
		output = output[:16000] + "\n[truncated]"
	}
	body := map[string]any{"nonce": cmd.Nonce, "status": status, "output": output}
	if exitCode != nil {
		body["exit_code"] = *exitCode
	}
	if len(resultData) > 0 {
		body["result_data"] = resultData
	}
	return c.postJSON(ctx, "/api/agent/commands/"+cmd.ID+"/result", body, nil)
}

// Ack sends the final acknowledgement of a wipe_device command. It succeeds
// only when the server confirms with {"proceed": true}.
func (c *Client) Ack(ctx context.Context, cmd model.Command) error {
	var out struct {
		Proceed bool `json:"proceed"`
	}
	if err := c.postJSON(ctx, "/api/agent/commands/"+cmd.ID+"/ack", map[string]string{"nonce": cmd.Nonce}, &out); err != nil {
		return err
	}
	if !out.Proceed {
		return errors.New("server did not confirm the acknowledgement")
	}
	return nil
}

// UploadLogs uploads a gzip log bundle for a collect_logs command.
func (c *Client) UploadLogs(ctx context.Context, cmd model.Command, gz []byte) error {
	return c.do(ctx, http.MethodPost, "/api/agent/commands/"+cmd.ID+"/logs", "application/gzip", gz,
		map[string]string{"X-Command-Nonce": cmd.Nonce}, nil)
}

// Fetch downloads an /api/agent/updates/ or /api/agent/scripts/ resource into
// w (at most max bytes; more is an error). Only paths on the enrolled server
// are ever fetched.
func (c *Client) Fetch(ctx context.Context, path string, max int64, w io.Writer) (int64, error) {
	allowed := strings.HasPrefix(path, "/api/agent/updates/") || strings.HasPrefix(path, "/api/agent/scripts/")
	if !allowed || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") {
		return 0, fmt.Errorf("refusing to fetch %q", path)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Authorization", "Bearer "+c.secret)
	resp, err := c.dl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))
		return 0, &HTTPError{Status: resp.StatusCode, Detail: strings.TrimSpace(string(b))}
	}
	if resp.ContentLength > max {
		return 0, fmt.Errorf("%w: response of %d bytes exceeds the %d byte limit", update.ErrSizeMismatch, resp.ContentLength, max)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return n, err
	}
	if n > max {
		return n, fmt.Errorf("%w: response exceeds the %d byte limit", update.ErrSizeMismatch, max)
	}
	return n, nil
}

// ReportUpdate sends an update status (downloading, verified, installed, rolled_back, ...).
func (c *Client) ReportUpdate(ctx context.Context, r update.Report) error {
	return c.postJSON(ctx, "/api/agent/updates/status", r, nil)
}
