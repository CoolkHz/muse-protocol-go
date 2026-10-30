package wsock

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRejectedUpgradeDoesNotExposeResponseOrToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "private-response "+r.URL.Query().Get("auth_token"), http.StatusUnauthorized)
	}))
	defer server.Close()
	_, err := Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http")+"/?auth_token=synthetic-session-secret", Options{Proxy: "direct"})
	var refused *HandshakeError
	if !errors.As(err, &refused) || refused.Status != http.StatusUnauthorized {
		t.Fatalf("expected classified unauthorized upgrade, got %v", err)
	}
	if strings.Contains(err.Error(), "private-response") || strings.Contains(err.Error(), "synthetic-session-secret") {
		t.Fatal("upgrade error exposed response or credentials")
	}
}

func TestInvalidURLDoesNotExposeToken(t *testing.T) {
	_, err := Dial(context.Background(), "wss://bad%host/?auth_token=synthetic-session-secret", Options{})
	if err == nil || strings.Contains(err.Error(), "synthetic-session-secret") {
		t.Fatal("invalid URL error must not expose credentials")
	}
}
