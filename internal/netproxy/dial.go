package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func dialVia(ctx context.Context, proxy, target string) (net.Conn, error) {
	d := &net.Dialer{}
	if proxy == "" || proxy == Direct {
		return d.DialContext(ctx, "tcp", target)
	}
	pu, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("bad proxy: %w", err)
	}
	proxyHost := pu.Host
	if pu.Port() == "" {
		port := "1080"
		if pu.Scheme == "http" {
			port = "80"
		} else if pu.Scheme == "https" {
			port = "443"
		}
		proxyHost = net.JoinHostPort(pu.Hostname(), port)
	}
	conn, err := d.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("proxy dial: %w", err)
	}
	baseConn := conn
	stopCancel := context.AfterFunc(ctx, func() { _ = baseConn.Close() })
	defer stopCancel()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if pu.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: pu.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	finish := func() (net.Conn, error) {
		if !stopCancel() || ctx.Err() != nil {
			conn.Close()
			return nil, ctx.Err()
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	}
	switch pu.Scheme {
	case "http", "https":
		req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
		if pu.User != nil {
			pw, _ := pu.User.Password()
			req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pw)) + "\r\n"
		}
		if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
			conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT: %s", resp.Status)
		}
		if br.Buffered() > 0 {
			conn.Close()
			return nil, errors.New("proxy sent data before tunnel was ready")
		}
		return finish()
	case "socks5", "socks5h":
		if err := socks5(conn, pu, target); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: %w", err)
		}
		return finish()
	}
	conn.Close()
	return nil, fmt.Errorf("unsupported proxy scheme %q", pu.Scheme)
}

func socks5(conn net.Conn, pu *url.URL, target string) error {
	methods := []byte{0x00}
	if pu.User != nil {
		methods = []byte{0x02}
	}
	if _, err := conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var rep [2]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return err
	}
	if rep[0] != 5 {
		return errors.New("invalid SOCKS version")
	}
	if rep[1] != methods[0] {
		return errors.New("proxy selected an unsupported authentication method")
	}
	if rep[1] == 0x02 {
		if pu.User == nil {
			return errors.New("proxy requires credentials")
		}
		user := pu.User.Username()
		pw, _ := pu.User.Password()
		if len(user) > 255 || len(pw) > 255 {
			return errors.New("SOCKS credentials too long")
		}
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(append(msg, byte(len(pw))), pw...)
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		if _, err := io.ReadFull(conn, rep[:]); err != nil {
			return err
		}
		if rep[0] != 1 || rep[1] != 0 {
			return errors.New("authentication failed")
		}
	} else if rep[1] != 0 {
		return errors.New("no acceptable auth method")
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil || len(host) > 255 {
		return errors.New("invalid SOCKS target")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid SOCKS target port")
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != 5 || head[2] != 0 {
		return errors.New("invalid SOCKS reply")
	}
	if head[1] != 0 {
		return fmt.Errorf("connect failed (code %d)", head[1])
	}
	skip := 0
	switch head[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return errors.New("invalid SOCKS reply address type")
	}
	_, err = io.ReadFull(conn, make([]byte, skip+2))
	return err
}
