package remote

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/Amechi-demigod/CloudSecurity/endpoint-agent/internal/version"
)

// TokenHeader carries the single-use session token on the WebSocket handshake.
const TokenHeader = "X-Remote-Session-Token"

// maxServerMessage bounds what the device accepts from the relay (control
// messages only: input, acks, end).
const maxServerMessage = 64 << 10

// DialConfig is how the agent reaches its enrolled server (internal/client).
type DialConfig struct {
	ServerURL   string      // enrolled base URL (https://; http:// only with InsecureDev)
	TLS         *tls.Config // pinned CA when the agent was enrolled with one
	Secret      string      // device credential
	InsecureDev bool
}

// NewDialer returns a DialFunc for the enrolled server. The URL is always
// derived from the enrolled server URL, never from the command, and
// redirects are refused, so the credential only ever goes to that server.
func NewDialer(cfg DialConfig) DialFunc {
	return func(ctx context.Context, sessionID, token string) (Conn, error) {
		u, err := relayURL(cfg.ServerURL, sessionID, cfg.InsecureDev)
		if err != nil {
			return nil, err
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if cfg.TLS != nil {
			tr.TLSClientConfig = cfg.TLS.Clone()
		}
		hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed")
		}}
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer "+cfg.Secret)
		hdr.Set(TokenHeader, token)
		hdr.Set("User-Agent", version.UserAgent())
		hdr.Set("X-CNAPP-Agent-Features", version.Features)
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		c, resp, err := websocket.Dial(dctx, u, &websocket.DialOptions{HTTPClient: hc, HTTPHeader: hdr})
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, err
		}
		c.SetReadLimit(maxServerMessage)
		return &wsConn{c: c}, nil
	}
}

func relayURL(server, sessionID string, insecureDev bool) (string, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL %q", server)
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		if !insecureDev {
			return "", errors.New("refusing a plain ws:// relay connection (enrolled without --insecure-dev)")
		}
		u.Scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported server URL scheme %q", u.Scheme)
	}
	if !sessionIDRe.MatchString(sessionID) {
		return "", errors.New("invalid session id")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/agent/remote/" + sessionID
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

type wsConn struct{ c *websocket.Conn }

func (w *wsConn) Read(ctx context.Context) (bool, []byte, error) {
	t, data, err := w.c.Read(ctx)
	return t == websocket.MessageBinary, data, err
}

func (w *wsConn) Write(ctx context.Context, binary bool, data []byte) error {
	t := websocket.MessageText
	if binary {
		t = websocket.MessageBinary
	}
	return w.c.Write(ctx, t, data)
}

func (w *wsConn) Close(code int, reason string) error {
	if len(reason) > 100 {
		reason = reason[:100]
	}
	return w.c.Close(websocket.StatusCode(code), reason)
}
