package netscan

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// PortInfo is one open port (contract: open_ports[]).
type PortInfo struct {
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service,omitempty"`
	Banner  string `json:"banner,omitempty"`
}

var serviceNames = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 515: "lpd",
	631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5900: "vnc", 8080: "http",
	8443: "https", 9100: "jetdirect"}

// silentPorts are services that never speak first; reading a banner would
// only cost a second.
var silentPorts = map[int]bool{135: true, 139: true, 445: true, 3389: true, 5985: true, 5986: true, 9100: true}

const (
	maxBanner     = 200
	bannerWait    = time.Second
	httpReadLimit = 8192
)

// cleanBanner drops control characters and anything that is not valid text.
func cleanBanner(b []byte, n int) string {
	s := strings.ToValidUTF8(string(b), "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// checkTCP connects to ip:port. It reports whether the port is open and, for
// open ports, the service name and a short banner: what the service sends
// unprompted within a second, or (HTTP ports) the status line and Server
// header of a plain GET /. Nothing else is ever sent and no credentials.
func (e *Env) checkTCP(ctx context.Context, ip string, port int, timeout time.Duration) (PortInfo, bool) {
	return e.checkTCPAs(ctx, ip, port, kindOf(port), timeout)
}

const (
	kindBanner = iota // read what the service sends unprompted
	kindSilent        // services that never speak first
	kindHTTP
	kindHTTPS
)

func kindOf(port int) int {
	switch {
	case port == 80 || port == 8080:
		return kindHTTP
	case port == 443 || port == 8443:
		return kindHTTPS
	case silentPorts[port]:
		return kindSilent
	}
	return kindBanner
}

func (e *Env) checkTCPAs(ctx context.Context, ip string, port, kind int, timeout time.Duration) (PortInfo, bool) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := e.dial(cctx, "tcp", addr)
	if err != nil {
		return PortInfo{}, false
	}
	defer conn.Close()
	info := PortInfo{Port: port, Proto: "tcp", Service: serviceNames[port]}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	switch kind {
	case kindHTTP:
		info.Banner = httpBanner(conn, ip)
	case kindHTTPS:
		_ = conn.SetDeadline(time.Now().Add(timeout + 2*time.Second))
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}) //nolint:gosec // only headers are read, nothing is trusted or sent
		hctx, hcancel := context.WithTimeout(ctx, timeout+2*time.Second)
		defer hcancel()
		if tc.HandshakeContext(hctx) == nil {
			info.Banner = httpBanner(tc, ip)
		}
	case kindBanner:
		_ = conn.SetReadDeadline(time.Now().Add(bannerWait))
		buf := make([]byte, maxBanner)
		n, _ := conn.Read(buf)
		info.Banner = cleanBanner(buf[:n], maxBanner)
	}
	return info, true
}

// httpBanner sends a minimal HTTP/1.0 GET / and keeps the status line and
// the Server header only.
func httpBanner(c net.Conn, host string) string {
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: cnapp-discovery\r\nAccept: */*\r\nConnection: close\r\n\r\n")); err != nil {
		return ""
	}
	r := bufio.NewReaderSize(&limitedConn{c: c, left: httpReadLimit}, 4096)
	status, err := r.ReadString('\n')
	if err != nil && status == "" {
		return ""
	}
	status = cleanBanner([]byte(status), 120)
	if !strings.HasPrefix(status, "HTTP/") {
		return ""
	}
	server := ""
	for i := 0; i < 64; i++ {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "server") {
			server = cleanBanner([]byte(v), 80)
			break
		}
		if err != nil {
			break
		}
	}
	if server != "" {
		return status + " | Server: " + server
	}
	return status
}

type limitedConn struct {
	c    net.Conn
	left int
}

func (l *limitedConn) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, net.ErrClosed
	}
	if len(p) > l.left {
		p = p[:l.left]
	}
	n, err := l.c.Read(p)
	l.left -= n
	return n, err
}
