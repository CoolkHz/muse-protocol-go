package login

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestMissingCredentialProviderFailsBeforeNetwork(t *testing.T) {
	o := Options{
		Email: "owner@example.com",
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("network used without a supplied password or code callback")
			return nil, nil
		}),
	}
	if result, err := Login(context.Background(), o); err == nil || result != nil {
		t.Fatal("missing credential provider accepted")
	}
}

func TestOTPCallbackReceivesAttemptTimeAfterSend(t *testing.T) {
	f := &loginFixture{t: t}
	o := fixtureOptions(f)
	started := time.Now()
	calls := 0
	o.GetOTP = func(ctx context.Context, sentAt time.Time) (string, error) {
		calls++
		if f.sends != 1 || f.confirms != 0 || sentAt.Before(started) || sentAt.After(time.Now()) {
			t.Fatal("callback did not follow the current code-send request")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("callback lacks login timeout")
		}
		return " 456789 ", nil
	}
	result, err := Login(context.Background(), o)
	if err != nil || result == nil || calls != 1 || f.receivedCode != "456789" || f.confirms != 1 {
		t.Fatalf("callback login failed: calls=%d confirmations=%d err=%v", calls, f.confirms, err)
	}
}

func TestOTPCallbackCancellationAndFailureNeverConfirm(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout", "failure", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			f := &loginFixture{t: t}
			o := fixtureOptions(f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var want error
			if mode == "timeout" {
				o.Timeout = 30 * time.Millisecond
				want = context.DeadlineExceeded
			}
			o.GetOTP = func(callbackCtx context.Context, _ time.Time) (string, error) {
				switch mode {
				case "cancel":
					want = context.Canceled
					cancel()
					<-callbackCtx.Done()
					return "", callbackCtx.Err()
				case "timeout":
					<-callbackCtx.Done()
					return "", callbackCtx.Err()
				case "failure":
					return "", errors.New("provider-secret=synthetic-sensitive-token")
				default:
					return "synthetic-sensitive-token", nil
				}
			}
			started := time.Now()
			result, err := Login(ctx, o)
			if result != nil || err == nil || f.confirms != 0 || time.Since(started) > time.Second {
				t.Fatalf("callback failure did not stop promptly: err=%v", err)
			}
			if want != nil && !errors.Is(err, want) {
				t.Fatalf("context error lost: %v", err)
			}
			if strings.Contains(err.Error(), "synthetic-sensitive-token") {
				t.Fatal("callback secret exposed through error")
			}
		})
	}
}

func TestOptionsJSONOmitsCredentialInputs(t *testing.T) {
	f, o := newPasswordFixture(t)
	o.Proxy = "http://synthetic-user:synthetic-proxy-password@proxy.example:8080"
	encoded, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{f.password, "synthetic-user", "synthetic-proxy-password"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("options JSON exposed credential input")
		}
	}
}
