package hatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestConnectValidatesCredentialsAndEndpoint(t *testing.T) {
	if _, err := Connect(context.Background(), nil, Options{}); err == nil {
		t.Fatal("nil session accepted")
	}
	s := &Session{VMID: "synthetic-vm", AuthToken: "synthetic-token"}
	for _, endpoint := range []string{"http://example.com", "ws://example.com/noise", "wss://user:secret@example.com/noise", "wss://example.com/noise?token=secret"} {
		if _, err := Connect(context.Background(), s, Options{URL: endpoint}); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
}

func TestTokensAndHandshakeBodyAreNotSerializedOrFormatted(t *testing.T) {
	const secret = "synthetic-secret-value"
	b, err := json.Marshal(Session{VMID: "synthetic-vm", AuthToken: secret, NotaryToken: secret})
	if err != nil || strings.Contains(string(b), secret) {
		t.Fatalf("unsafe session JSON: %s %v", b, err)
	}
	cause := errors.New(secret)
	for _, status := range []int{0, 401} {
		err := &HandshakeError{Status: status, Err: cause}
		if strings.Contains(err.Error(), secret) || !errors.Is(err, cause) {
			t.Fatal("handshake leaked detail or lost cause")
		}
	}
}
