package netproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bridge exposes an ephemeral loopback HTTP proxy. Chromium never receives
// upstream credentials; HTTP CONNECT and SOCKS authentication happen in Go.
type Bridge struct {
	listener net.Listener
	server   *http.Server
	client   *http.Client
	proxy    string
	mu       sync.Mutex
	closed   bool
	tunnels  map[net.Conn]struct{}
}

func StartBridge(proxy string) (*Bridge, error) {
	p, err := Normalize(proxy)
	if err != nil {
		return nil, err
	}
	if p == "" {
		return nil, errors.New("浏览器代理桥接前必须先解析继承设置")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	b := &Bridge{listener: ln, proxy: p, client: NewHTTPClient(p, 0), tunnels: map[net.Conn]struct{}{}}
	b.server = &http.Server{Handler: b, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: time.Minute}
	go func() { _ = b.server.Serve(ln) }()
	return b, nil
}
func (b *Bridge) URL() string { return "http://" + b.listener.Addr().String() }
func (b *Bridge) Close() error {
	b.mu.Lock()
	b.closed = true
	for conn := range b.tunnels {
		_ = conn.Close()
	}
	b.mu.Unlock()
	b.client.CloseIdleConnections()
	return b.server.Close()
}
func (b *Bridge) track(conns ...net.Conn) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		for _, c := range conns {
			_ = c.Close()
		}
		return false
	}
	for _, c := range conns {
		b.tunnels[c] = struct{}{}
	}
	return true
}
func (b *Bridge) untrack(conns ...net.Conn) {
	b.mu.Lock()
	for _, c := range conns {
		delete(b.tunnels, c)
		_ = c.Close()
	}
	b.mu.Unlock()
}

func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		b.tunnel(w, r)
		return
	}
	if !r.URL.IsAbs() || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
		http.Error(w, "absolute HTTP URL required", 400)
		return
	}
	req := r.Clone(r.Context())
	req.RequestURI = ""
	req.Header = r.Header.Clone()
	stripHopHeaders(req.Header)
	// Downstream applications may not inject the upstream proxy's credentials.
	req.Header.Del("Proxy-Authorization")
	resp, err := b.client.Do(req)
	if err != nil {
		http.Error(w, "upstream proxy request failed", 502)
		return
	}
	defer resp.Body.Close()
	stripHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
func stripHopHeaders(h http.Header) {
	for _, token := range splitHeaderTokens(h.Values("Connection")) {
		h.Del(token)
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(key)
	}
}
func (b *Bridge) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	n, e := strconv.Atoi(port)
	if err != nil || host == "" || e != nil || n < 1 || n > 65535 {
		http.Error(w, "invalid CONNECT target", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	upstream, err := DialContext(ctx, b.proxy, net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		http.Error(w, "upstream proxy connection failed", 502)
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "tunneling unavailable", 500)
		return
	}
	downstream, rw, err := h.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if !b.track(upstream, downstream) {
		return
	}
	defer b.untrack(upstream, downstream)
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, rw); _ = upstream.Close(); close(done) }()
	_, _ = io.Copy(downstream, upstream)
	_ = downstream.Close()
	_ = upstream.Close()
	<-done
}

func splitHeaderTokens(values []string) []string {
	var tokens []string
	for _, v := range values {
		for _, token := range strings.Split(v, ",") {
			if token = strings.TrimSpace(token); token != "" {
				tokens = append(tokens, token)
			}
		}
	}
	return tokens
}
