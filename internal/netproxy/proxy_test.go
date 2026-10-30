package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeAndRedact(t *testing.T) {
	cases := map[string]string{"": "", "direct": "direct", "direct://": "direct", "host.test:8080": "http://host.test:8080", "host.test:8080:user:pass": "http://user:pass@host.test:8080", "socks5://u:p@host.test": "socks5://u:p@host.test:1080", "https://HOST.test/": "https://host.test:443", "[::1]:8080": "http://[::1]:8080"}
	for input, want := range cases {
		got, err := Normalize(input)
		if err != nil || got != want {
			t.Errorf("Normalize(%q)=%q,%v want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"file:///tmp/proxy", "http://", "http://host.test:0", "http://host.test:70000", "http://host.test/path", "http://host.test?q=x", "http://secret-user:secret-pass@host.test:bad", "http://host.test\nX: yes"} {
		if _, err := Normalize(input); err == nil {
			t.Errorf("accepted %q", input)
		} else if strings.Contains(err.Error(), "secret-") {
			t.Fatal("validation leaked credentials")
		}
	}
	got := Redact("http://secret-user:secret-pass@host.test:8000")
	if strings.Contains(got, "secret-") || !strings.Contains(got, "host.test:8000") {
		t.Fatalf("redaction=%s", got)
	}
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"} {
		t.Setenv(key, "")
	}
}
func TestEffectiveRoutesAndNoProxy(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://global.test:3128")
	t.Setenv("ALL_PROXY", "socks5://fallback.test:1080")
	t.Setenv("NO_PROXY", ".internal.test,10.0.0.0/8,exact.test:443")
	for _, tc := range []struct{ account, global, target, want string }{
		{"", "", "https://muse.test", "http://global.test:3128"},
		{"direct", "http://global.test:3128", "https://muse.test", "direct"},
		{"http://account.test:9000", "direct", "https://muse.test", "http://account.test:9000"},
		{"", "", "http://muse.test", "socks5://fallback.test:1080"},
		{"", "", "https://foo.internal.test", "direct"},
		{"", "", "https://10.1.2.3", "direct"},
		{"", "", "https://exact.test", "direct"},
		{"", "", "http://exact.test", "socks5://fallback.test:1080"},
	} {
		got, err := Resolve(Effective(tc.account, tc.global), tc.target)
		if err != nil || got != tc.want {
			t.Errorf("route(%+v)=%q %v", tc, got, err)
		}
	}
	// Explicit proxy overrides NO_PROXY, including local destinations in tests.
	got, err := Resolve("http://account.test:9000", "http://127.0.0.1:80")
	if err != nil || got != "http://account.test:9000" {
		t.Fatal(got, err)
	}
}

func TestSafeErrorPreservesClassification(t *testing.T) {
	proxy := "http://secret-user:secret-pass@host.test:8000"
	err := SafeError(&url.Error{Op: "Get", URL: proxy, Err: context.DeadlineExceeded}, proxy)
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "secret-") {
		t.Fatal(err)
	}
}

func httpProxy(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-password"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Proxy-Authorization") != expected {
			http.Error(w, "authentication required", 407)
			return
		}
		if r.Method == http.MethodConnect {
			remote, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, "dial failed", 502)
				return
			}
			conn, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				remote.Close()
				return
			}
			defer conn.Close()
			defer remote.Close()
			_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = rw.Flush()
			done := make(chan struct{})
			go func() { _, _ = io.Copy(remote, rw); remote.Close(); close(done) }()
			_, _ = io.Copy(conn, remote)
			conn.Close()
			<-done
			return
		}
		req := r.Clone(r.Context())
		req.RequestURI = ""
		req.Header = req.Header.Clone()
		req.Header.Del("Proxy-Authorization")
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		defer transport.CloseIdleConnections()
		resp, err := transport.RoundTrip(req)
		if err != nil {
			http.Error(w, "forward failed", 502)
			return
		}
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	u.User = url.UserPassword("proxy-user", "proxy-password")
	return u.String(), calls
}

func socksProxy(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var head [4]byte
				if _, err := io.ReadFull(conn, head[:2]); err != nil {
					return
				}
				methods := make([]byte, int(head[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				_, _ = conn.Write([]byte{5, 2})
				if _, err := io.ReadFull(conn, head[:2]); err != nil {
					return
				}
				user := make([]byte, int(head[1]))
				if _, err := io.ReadFull(conn, user); err != nil {
					return
				}
				if _, err := io.ReadFull(conn, head[:1]); err != nil {
					return
				}
				password := make([]byte, int(head[0]))
				if _, err := io.ReadFull(conn, password); err != nil {
					return
				}
				if string(user) != "proxy-user" || string(password) != "proxy-password" {
					_, _ = conn.Write([]byte{1, 1})
					return
				}
				_, _ = conn.Write([]byte{1, 0})
				if _, err := io.ReadFull(conn, head[:]); err != nil {
					return
				}
				var host string
				switch head[3] {
				case 1:
					b := make([]byte, 4)
					if _, err := io.ReadFull(conn, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 4:
					b := make([]byte, 16)
					if _, err := io.ReadFull(conn, b); err != nil {
						return
					}
					host = net.IP(b).String()
				case 3:
					if _, err := io.ReadFull(conn, head[:1]); err != nil {
						return
					}
					b := make([]byte, int(head[0]))
					if _, err := io.ReadFull(conn, b); err != nil {
						return
					}
					host = string(b)
				default:
					return
				}
				if _, err := io.ReadFull(conn, head[:2]); err != nil {
					return
				}
				port := int(head[0])*256 + int(head[1])
				remote, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					return
				}
				defer remote.Close()
				calls.Add(1)
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				_ = conn.SetDeadline(time.Time{})
				done := make(chan struct{})
				go func() { _, _ = io.Copy(remote, conn); remote.Close(); close(done) }()
				_, _ = io.Copy(conn, remote)
				conn.Close()
				<-done
			}()
		}
	}()
	return "socks5://proxy-user:proxy-password@" + ln.Addr().String(), calls
}

func TestAuthenticatedProxyHTTPAndBrowserBridge(t *testing.T) {
	for _, kind := range []string{"http", "socks5"} {
		t.Run(kind, func(t *testing.T) {
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Proxy-Authorization") != "" {
					t.Error("proxy credentials reached target")
				}
				_, _ = io.WriteString(w, "routed")
			}))
			defer target.Close()
			var proxy string
			var calls *atomic.Int32
			if kind == "http" {
				proxy, calls = httpProxy(t)
			} else {
				proxy, calls = socksProxy(t)
			}
			bridge, err := StartBridge(proxy)
			if err != nil {
				t.Fatal(err)
			}
			defer bridge.Close()
			for _, route := range []string{proxy, bridge.URL()} {
				client := NewHTTPClient(route, 2*time.Second)
				client.Transport.(*safeTransport).base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
				resp, err := client.Get(target.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				client.CloseIdleConnections()
				if err != nil || string(body) != "routed" {
					t.Fatalf("body=%s err=%v", body, err)
				}
			}
			if calls.Load() != 2 {
				t.Fatalf("route bypassed upstream proxy: calls=%d", calls.Load())
			}
		})
	}
}

func TestDirectAndInvalidProxyFailClosed(t *testing.T) {
	clearProxyEnv(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "direct") }))
	defer target.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	client := NewHTTPClient(Direct, time.Second)
	defer client.CloseIdleConnections()
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	invalid := NewHTTPClient("ftp://secret-user:secret-pass@proxy.test", time.Second)
	defer invalid.CloseIdleConnections()
	if resp, err := invalid.Get(target.URL); err == nil {
		resp.Body.Close()
		t.Fatal("invalid proxy fell back to direct")
	} else if strings.Contains(err.Error(), "secret-") {
		t.Fatal("error leaked credentials")
	}
}

func TestDialProxyCancellationAndBridgeClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = DialContext(ctx, "socks5://"+ln.Addr().String(), "example.test:443")
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("stalled proxy didn't cancel: %v", err)
	}
	conn := <-accepted
	conn.Close()
	bridge, err := StartBridge(Direct)
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.TrimPrefix(bridge.URL(), "http://")
	client, err := net.Dial("tcp", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = bridge.Close()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err = bufio.NewReader(client).ReadByte()
	if err == nil {
		t.Fatal("closed bridge retained connection")
	}
}
