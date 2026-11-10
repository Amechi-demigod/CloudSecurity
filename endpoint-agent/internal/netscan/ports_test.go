package netscan

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func listen(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback TCP: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func TestTCPOpenClosedAndBanner(t *testing.T) {
	ssh := listen(t, func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n\x01\x02")) })
	silent := listen(t, func(c net.Conn) { time.Sleep(300 * time.Millisecond) })
	long := listen(t, func(c net.Conn) { _, _ = c.Write([]byte(strings.Repeat("A", 1000))) })
	e := &Env{}
	ctx := context.Background()
	info, ok := e.checkTCPAs(ctx, "127.0.0.1", ssh, kindBanner, time.Second)
	if !ok || info.Port != ssh || info.Proto != "tcp" || info.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("%+v %v", info, ok)
	}
	info, ok = e.checkTCPAs(ctx, "127.0.0.1", silent, kindBanner, time.Second)
	if !ok || info.Banner != "" {
		t.Errorf("%+v %v", info, ok)
	}
	info, ok = e.checkTCPAs(ctx, "127.0.0.1", long, kindBanner, time.Second)
	if !ok || len(info.Banner) != maxBanner {
		t.Errorf("banner of %d bytes", len(info.Banner))
	}
	// a service name for well-known ports
	if kindOf(22) != kindBanner || kindOf(445) != kindSilent || kindOf(8443) != kindHTTPS || kindOf(80) != kindHTTP {
		t.Error("port kinds")
	}
	// closed port: grab a free port and close it
	l, _ := net.Listen("tcp4", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if _, ok := e.checkTCPAs(ctx, "127.0.0.1", closed, kindBanner, 500*time.Millisecond); ok {
		t.Error("closed port reported open")
	}
}

func TestCleanBannerStripsControlCharacters(t *testing.T) {
	got := cleanBanner([]byte("\x1b[31mlogin:\x00 \r\nuser\x7f\xff"), 200)
	if strings.ContainsAny(got, "\x1b\x00\r\n\x7f") || !strings.HasPrefix(got, "[31mlogin:") {
		t.Errorf("%q", got)
	}
}

func TestHTTPStatusAndServerHeader(t *testing.T) {
	var gotReq string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReq = r.Method + " " + r.URL.Path + " " + r.Proto + " host=" + r.Host + " auth=" + r.Header.Get("Authorization")
		w.Header().Set("Server", "TestServer/1.0")
		w.Header().Set("X-Secret", "must-not-be-kept")
		w.WriteHeader(401)
		_, _ = w.Write([]byte("<html>body must not be kept</html>"))
	}))
	defer srv.Close()
	port := portOf(t, srv.URL)
	info, ok := (&Env{}).checkTCPAs(context.Background(), "127.0.0.1", port, kindHTTP, time.Second)
	if !ok || info.Banner != "HTTP/1.0 401 Unauthorized | Server: TestServer/1.0" {
		t.Errorf("%+v", info)
	}
	if gotReq != "GET / HTTP/1.0 host=127.0.0.1 auth=" {
		t.Errorf("request %q", gotReq)
	}
	if strings.Contains(info.Banner, "must-not") || strings.Contains(info.Banner, "body") {
		t.Error("kept more than the status line and Server header")
	}
}

func TestHTTPSWithSelfSignedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TLSBox")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	info, ok := (&Env{}).checkTCPAs(context.Background(), "127.0.0.1", portOf(t, srv.URL), kindHTTPS, time.Second)
	if !ok || info.Banner != "HTTP/1.0 200 OK | Server: TLSBox" {
		t.Errorf("%+v", info)
	}
}

func TestHTTPNoServerHeaderAndNonHTTP(t *testing.T) {
	plain := listen(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})
	info, ok := (&Env{}).checkTCPAs(context.Background(), "127.0.0.1", plain, kindHTTP, time.Second)
	if !ok || info.Banner != "HTTP/1.1 200 OK" {
		t.Errorf("%+v", info)
	}
	notHTTP := listen(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("garbage that is not http\r\n"))
	})
	info, ok = (&Env{}).checkTCPAs(context.Background(), "127.0.0.1", notHTTP, kindHTTP, time.Second)
	if !ok || info.Banner != "" {
		t.Errorf("%+v", info)
	}
}

func TestPortCheckHonoursContext(t *testing.T) {
	hang := listen(t, func(c net.Conn) { time.Sleep(5 * time.Second) })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	start := time.Now()
	(&Env{}).checkTCPAs(ctx, "127.0.0.1", hang, kindHTTP, 4*time.Second)
	if time.Since(start) > 2*time.Second {
		t.Errorf("not cancelled: %s", time.Since(start))
	}
}

func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(u.Port())
	return n
}
