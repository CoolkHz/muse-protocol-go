// Package netproxy provides one outbound proxy policy for HTTP, WebSocket and
// browser traffic. A blank setting inherits; "direct" explicitly bypasses it.
package netproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const Direct = "direct"

// Normalize accepts proxy URLs or host:port[:user:password] shorthand. Errors
// intentionally omit the input because it may contain credentials.
func Normalize(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if strings.EqualFold(raw, Direct) || strings.EqualFold(raw, "direct://") {
		return Direct, nil
	}
	if strings.ContainsAny(raw, "\r\n\t ") {
		return "", errors.New("代理地址不能包含空白字符")
	}
	if !strings.Contains(raw, "://") {
		if !strings.HasPrefix(raw, "[") {
			parts := strings.SplitN(raw, ":", 4)
			if len(parts) == 4 {
				u := url.URL{Scheme: "http", Host: net.JoinHostPort(parts[0], parts[1]), User: url.UserPassword(parts[2], parts[3])}
				raw = u.String()
			} else {
				raw = "http://" + raw
			}
		} else {
			raw = "http://" + raw
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("代理 URL 格式无效")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return "", errors.New("代理协议仅支持 http、https、socks5、socks5h")
	}
	if u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("代理地址必须只包含协议、主机、端口和可选认证信息")
	}
	if strings.ContainsAny(u.Hostname(), "\\/@%") {
		return "", errors.New("代理主机名无效")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("代理端口必须在 1–65535 范围内")
		}
	} else {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "1080"
		}
	}
	if u.User != nil {
		pw, _ := u.User.Password()
		if u.User.Username() == "" {
			return "", errors.New("代理用户名不能为空")
		}
		if (u.Scheme == "socks5" || u.Scheme == "socks5h") && (len(u.User.Username()) > 255 || len(pw) > 255) {
			return "", errors.New("SOCKS5 用户名和密码最多各 255 字节")
		}
	}
	u.Host = net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	u.Path = ""
	u.RawPath = ""
	return u.String(), nil
}

func Effective(account, global string) string {
	if strings.TrimSpace(account) != "" {
		return account
	}
	return global
}
func env(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return os.Getenv(strings.ToLower(key))
}

// Resolve resolves inheritance once for a target. Both uppercase/lowercase
// HTTP(S)_PROXY, ALL_PROXY and NO_PROXY are supported without a stale env cache.
func Resolve(raw, target string) (string, error) {
	if strings.TrimSpace(raw) != "" {
		return Normalize(raw)
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("代理目标 URL 无效")
	}
	scheme := u.Scheme
	if scheme == "wss" {
		scheme = "https"
	}
	if scheme == "ws" {
		scheme = "http"
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if scheme == "https" {
			port = "443"
		}
	}
	if bypass(u.Hostname(), port, env("NO_PROXY")) {
		return Direct, nil
	}
	proxy := ""
	if scheme == "https" {
		proxy = env("HTTPS_PROXY")
	} else {
		proxy = env("HTTP_PROXY")
	}
	if proxy == "" {
		proxy = env("ALL_PROXY")
	}
	if proxy == "" {
		return Direct, nil
	}
	return Normalize(proxy)
}
func bypass(host, port, rules string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return true
	}
	for _, entry := range strings.Split(rules, ",") {
		entry = strings.TrimSpace(strings.ToLower(entry))
		if entry == "" {
			continue
		}
		if entry == "*" {
			return true
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			if ip != nil && network.Contains(ip) {
				return true
			}
			continue
		}
		h, p, err := net.SplitHostPort(entry)
		if err == nil {
			if p != port {
				continue
			}
			entry = h
		}
		entry = strings.Trim(entry, "[]")
		if other := net.ParseIP(entry); other != nil {
			if ip != nil && other.Equal(ip) {
				return true
			}
			continue
		}
		subdomainsOnly := strings.HasPrefix(entry, ".") || strings.HasPrefix(entry, "*.")
		entry = strings.TrimPrefix(strings.TrimPrefix(entry, "*"), ".")
		if (!subdomainsOnly && host == entry) || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

func Redact(raw string) string {
	normalized, err := Normalize(raw)
	if err != nil {
		return "[invalid proxy]"
	}
	if normalized == "" || normalized == Direct {
		return normalized
	}
	u, _ := url.Parse(normalized)
	if u.User != nil {
		u.User = url.UserPassword("redacted", "redacted")
	}
	return u.String()
}

type safeError struct {
	message string
	cause   error
}

func (e *safeError) Error() string { return e.message }
func (e *safeError) Unwrap() error { return e.cause }

// SafeError preserves error classification while removing proxy credentials.
func SafeError(err error, proxy string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	normalized, _ := Normalize(proxy)
	for _, raw := range []string{proxy, normalized} {
		if raw != "" && raw != Direct {
			msg = strings.ReplaceAll(msg, raw, Redact(raw))
		}
	}
	if u, e := url.Parse(normalized); e == nil && u.User != nil {
		pw, _ := u.User.Password()
		for _, secret := range []string{u.User.String(), pw, url.QueryEscape(pw), url.PathEscape(pw), u.User.Username()} {
			if secret != "" {
				msg = strings.ReplaceAll(msg, secret, "[redacted]")
			}
		}
	}
	return &safeError{message: msg, cause: err}
}

type safeTransport struct {
	base  *http.Transport
	proxy string
}

func (t *safeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	actual, _ := Resolve(t.proxy, req.URL.String())
	return resp, SafeError(err, actual)
}
func (t *safeTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

func NewHTTPClient(proxy string, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = func(req *http.Request) (*url.URL, error) {
		p, err := Resolve(proxy, req.URL.String())
		if err != nil {
			return nil, err
		}
		if p == Direct {
			return nil, nil
		}
		return url.Parse(p)
	}
	tr.MaxIdleConns = 64
	tr.MaxIdleConnsPerHost = 8
	return &http.Client{Timeout: timeout, Transport: &safeTransport{base: tr, proxy: proxy}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// CheckURL validates the configured fixed IP probe endpoint; it is never taken
// from a per-request target parameter.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("出口 IP 检查地址必须是无认证信息的 HTTP(S) URL")
	}
	return nil
}

// DialContext dials a TCP target through an already resolved route. Empty means
// direct for this low-level API; callers with URL context should use Resolve.
func DialContext(ctx context.Context, proxy, target string) (net.Conn, error) {
	normalized, err := Normalize(proxy)
	if err != nil {
		return nil, err
	}
	conn, err := dialVia(ctx, normalized, target)
	return conn, SafeError(err, normalized)
}
