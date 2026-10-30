package wsock

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type observedConn struct {
	net.Conn
	writing chan struct{}
}

func (c observedConn) Write(p []byte) (int, error) { close(c.writing); return c.Conn.Write(p) }

func TestCloseInterruptsBlockedWrite(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	c := &Conn{conn: observedConn{client, started}, br: bufio.NewReader(client), maxSize: 1024}
	result := make(chan error, 1)
	go func() { result <- c.WriteBinary([]byte("blocked")) }()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind an outstanding write")
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("write did not unblock")
	}
}

func TestCanceledWriterDoesNotWaitForWriteLock(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	c := &Conn{conn: observedConn{client, started}}
	result := make(chan error, 1)
	go func() { result <- c.WriteBinary([]byte("blocked")) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.WriteBinaryContext(ctx, []byte("second")); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	_ = c.Close()
	<-result
}

func TestWriteContextInterruptsTransport(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	started := make(chan struct{})
	c := &Conn{conn: observedConn{client, started}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- c.WriteBinaryContext(ctx, []byte("blocked")) }()
	<-started
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock write")
	}
}
