package login

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func reply(r *http.Request, status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: headers, Request: r}
}

type loginFixture struct {
	mu             sync.Mutex
	sends          int
	confirms       int
	authChecks     int
	authData       map[string]any
	sessionData    map[string]any
	invalidSession bool
	missingSession bool
	receivedCode   string
	mismatch       bool
	gate           bool
	transportError bool
	paths          []string
	t              *testing.T
}

func (f *loginFixture) transport(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Host+r.URL.Path)
	if r.URL.Host != "muse.ai" {
		f.t.Fatalf("unexpected login origin: %s", r.URL.Host)
	}
	switch r.URL.Path {
	case "/":
		return reply(r, 200, "<html>login</html>", nil), nil
	case "/api/auth/native/restart":
		return reply(r, 200, `{"csrf_token":"secret-csrf"}`, http.Header{"Set-Cookie": {"native_state=state; Path=/; Secure; HttpOnly"}}), nil
	case "/api/auth/native/send-otp":
		if r.Method != "POST" || r.Header.Get("X-Hatch-CSRF-Token") != "secret-csrf" || r.Header.Get("X-Hatch-Waterfall-Id") == "" {
			f.t.Error("missing native auth headers")
		}
		cookie, err := r.Cookie("native_state")
		if err != nil || cookie.Value != "state" {
			f.t.Error("native state cookie missing")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["contact_point"] != "owner@example.com" {
			f.t.Errorf("contact_point=%v", body["contact_point"])
		}
		f.sends++
		if f.transportError {
			return nil, errors.New("sensitive https://private.example/secret-token proxyuser:proxypass otp=123456")
		}
		return reply(r, 200, `{"registration_state":"otp_sent"}`, nil), nil
	case "/api/auth/native/confirm-otp":
		f.confirms++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.receivedCode, _ = body["otp_code"].(string)
		if f.gate {
			return reply(r, 200, `{"registration_state":"completion_required","requires_name":true}`, nil), nil
		}
		headers := http.Header{"Set-Cookie": {"hatch_native_auth_device=device; Path=/; Secure; HttpOnly"}}
		if !f.missingSession {
			headers.Add("Set-Cookie", "hatch_sess=secret-session; Path=/; Max-Age=3600; Secure; HttpOnly")
		}
		return reply(r, 200, `{"registration_state":"logged_in"}`, headers), nil
	case "/api/auth/check":
		f.authChecks++
		if r.Method != http.MethodPost {
			return reply(r, http.StatusMethodNotAllowed, `{}`, http.Header{"Allow": {http.MethodPost}}), nil
		}
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err != nil || len(body) != 0 {
				f.t.Error("auth check must use the browser's bodyless POST")
			}
		}
		if r.Header.Get("Content-Type") != "" || r.Header.Get("Cache-Control") != "no-store" {
			f.t.Error("auth check must have no payload content type and must disable caching")
		}
		if cookie, err := r.Cookie("hatch_sess"); !f.missingSession && (err != nil || cookie.Value == "") {
			f.t.Error("auth check lacks the confirmed session cookie")
		}
		if f.authData != nil {
			data, _ := json.Marshal(f.authData)
			return reply(r, 200, string(data), nil), nil
		}
		email := "owner@example.com"
		if f.mismatch {
			email = "different@example.com"
		}
		return reply(r, 200, `{"authenticated":true,"user":{"email":"`+email+`"},"account_id":"account-1"}`, nil), nil
	case "/api/session":
		if r.Method != http.MethodGet {
			f.t.Error("session metadata must still use GET")
		}
		if f.invalidSession {
			return reply(r, 200, "not JSON", nil), nil
		}
		if f.sessionData != nil {
			data, _ := json.Marshal(f.sessionData)
			return reply(r, 200, string(data), nil), nil
		}
		return reply(r, 200, `{"status":"assigned","vm_id":"vm-1"}`, nil), nil
	}
	f.t.Errorf("unexpected endpoint %s", r.URL.Path)
	return reply(r, 404, `{}`, nil), nil
}
func fixtureOptions(f *loginFixture) Options {
	return Options{Email: " Owner@Example.COM ", GetOTP: func(context.Context, time.Time) (string, error) { return "333333", nil }, Proxy: "direct", Timeout: time.Second, Transport: roundTripFunc(f.transport)}
}

func TestCallbackLoginReturnsIdentity(t *testing.T) {
	f := &loginFixture{t: t}
	o := fixtureOptions(f)
	var phases []string
	o.OnStage = func(phase string) { phases = append(phases, phase) }
	result, err := Login(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if f.sends != 1 || f.confirms != 1 || f.authChecks != 1 || f.receivedCode != "333333" {
		t.Fatalf("sends=%d confirms=%d code=%q", f.sends, f.confirms, f.receivedCode)
	}
	if !result.IdentityVerified || result.Email != "owner@example.com" || result.AccountID != "account-1" || result.Cookies["hatch_sess"] != "secret-session" {
		t.Fatalf("unexpected result metadata: %s %t %s", result.Email, result.IdentityVerified, result.AccountID)
	}
	if result.CookieExpires["hatch_sess"] <= time.Now().Unix() {
		t.Fatal("cookie expiration missing")
	}
	if phases[len(phases)-1] != "completed" {
		t.Fatalf("phases %v", phases)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "secret-session") || strings.Contains(string(encoded), "device") {
		t.Fatal("result JSON exposed cookies")
	}
}

func TestLoginAuthCheckRejectsExplicitInvalidAuthenticatedForBothModes(t *testing.T) {
	for _, mode := range []string{"otp", "password"} {
		for _, tc := range []struct {
			name string
			data map[string]any
		}{
			{"false", map[string]any{"authenticated": false}},
			{"null", map[string]any{"authenticated": nil}},
			{"wrong type", map[string]any{"authenticated": "true"}},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				f := &loginFixture{t: t}
				o := fixtureOptions(f)
				o.GetOTP = func(context.Context, time.Time) (string, error) { return "123456", nil }
				if mode == "password" {
					var password *passwordFixture
					password, o = newPasswordFixture(t)
					f = password.base
				}
				f.authData = tc.data
				result, err := Login(context.Background(), o)
				var loginErr *Error
				if result != nil || !errors.As(err, &loginErr) || loginErr.Code != "session_not_authenticated" || loginErr.Stage != "verifying" || f.authChecks != 1 {
					t.Fatalf("unauthenticated session was not rejected: %v", err)
				}
				for _, path := range f.paths {
					if strings.HasSuffix(path, "/api/session") {
						t.Fatal("session metadata fetched after auth check rejected the session")
					}
				}
			})
		}
	}
}

func TestLoginMissingAuthFlagRequiresValidFinalSession(t *testing.T) {
	for _, mode := range []string{"otp", "password"} {
		for _, tc := range []struct {
			name   string
			mutate func(*loginFixture)
			code   string
		}{
			{"assigned", func(*loginFixture) {}, ""},
			{"malformed JSON", func(f *loginFixture) { f.invalidSession = true }, "session_not_authenticated"},
			{"empty JSON", func(f *loginFixture) { f.sessionData = map[string]any{} }, "session_not_authenticated"},
			{"unassigned", func(f *loginFixture) { f.sessionData = map[string]any{"status": "pending", "vm_id": "vm-1"} }, "session_not_authenticated"},
			{"anonymous", func(f *loginFixture) { f.sessionData = map[string]any{"status": "anonymous", "vm_id": "vm-1"} }, "session_not_authenticated"},
			{"missing VM", func(f *loginFixture) { f.sessionData = map[string]any{"status": "assigned"} }, "session_not_authenticated"},
			{"empty VM", func(f *loginFixture) { f.sessionData = map[string]any{"status": "assigned", "vm_id": "  "} }, "session_not_authenticated"},
			{"wrong VM type", func(f *loginFixture) { f.sessionData = map[string]any{"status": "assigned", "vm_id": 1} }, "session_not_authenticated"},
			{"missing cookie", func(f *loginFixture) { f.missingSession = true }, "missing_session_cookie"},
			{"identity mismatch", func(f *loginFixture) {
				f.sessionData = map[string]any{"status": "assigned", "vm_id": "vm-1", "user": map[string]any{"email": "different@example.com"}}
			}, "identity_mismatch"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				f := &loginFixture{t: t}
				o := fixtureOptions(f)
				o.GetOTP = func(context.Context, time.Time) (string, error) { return "123456", nil }
				var password *passwordFixture
				if mode == "password" {
					password, o = newPasswordFixture(t)
					f = password.base
				}
				f.authData = map[string]any{"ok": true}
				tc.mutate(f)
				result, err := Login(context.Background(), o)
				if tc.code == "" {
					if err != nil || result == nil || !result.IdentityVerified || result.SessionStatus != "assigned" || result.Cookies["hatch_sess"] == "" {
						t.Fatalf("valid session with missing auth flag was rejected: %v", err)
					}
				} else {
					var loginErr *Error
					if result != nil || !errors.As(err, &loginErr) || loginErr.Code != tc.code || loginErr.Stage != "verifying" {
						t.Fatalf("invalid session error: %v", err)
					}
				}
				if f.authChecks != 1 || f.sends != 1 || mode == "otp" && f.confirms != 1 || mode == "password" && (password.confirms != 1 || f.confirms != 0) {
					t.Fatal("session verification retried authentication")
				}
			})
		}
	}
}

func TestLoginRejectsIdentityMismatchAndRegistration(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mismatch, gate bool
		want           string
	}{{"identity", true, false, "identity_mismatch"}, {"registration", false, true, "manual_intervention"}} {
		t.Run(tc.name, func(t *testing.T) {
			f := &loginFixture{t: t, mismatch: tc.mismatch, gate: tc.gate}
			o := fixtureOptions(f)
			o.GetOTP = func(context.Context, time.Time) (string, error) { return "123456", nil }
			result, err := Login(context.Background(), o)
			var loginErr *Error
			if result != nil || !errors.As(err, &loginErr) || loginErr.Code != tc.want {
				t.Fatalf("result=%v error=%v", result, err)
			}
			if tc.gate && !errors.Is(err, ErrManualIntervention) {
				t.Fatal("registration gate not classified")
			}
			for _, path := range f.paths {
				if strings.Contains(path, "register-completion") || strings.Contains(path, "accept-tos") {
					t.Fatal("registration endpoint invoked")
				}
			}
		})
	}
}

func TestManualOTPIsCancelableAndNeverConfirmedAfterCancel(t *testing.T) {
	f := &loginFixture{t: t}
	o := fixtureOptions(f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.GetOTP = func(ctx context.Context, _ time.Time) (string, error) { cancel(); return "123456", nil }
	_, err := Login(ctx, o)
	if !errors.Is(err, context.Canceled) || f.confirms != 0 {
		t.Fatalf("cancellation err=%v confirms=%d", err, f.confirms)
	}
}

func TestLoginErrorsNeverExposeResponseOrTransportSecrets(t *testing.T) {
	f := &loginFixture{t: t, transportError: true}
	o := fixtureOptions(f)
	_, err := Login(context.Background(), o)
	if err == nil {
		t.Fatal("expected failure")
	}
	for _, secret := range []string{"secret-token", "proxyuser", "proxypass", "123456", "private.example"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error exposes %s", secret)
		}
	}
	if f.sends != 1 || f.confirms != 0 {
		t.Fatal("OTP request was retried")
	}
}

func TestNativeAuthRedirectDoesNotReplayPost(t *testing.T) {
	calls := 0
	o := Options{Email: "owner@example.com", Proxy: "direct", GetOTP: func(context.Context, time.Time) (string, error) { return "123456", nil }, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/" {
			return reply(r, 200, "home", nil), nil
		}
		if r.URL.Path == "/api/auth/native/restart" {
			return reply(r, 307, "", http.Header{"Location": {"https://evil.example/collect"}}), nil
		}
		t.Errorf("redirect target called: %s", r.URL.Host)
		return reply(r, 500, "", nil), nil
	})}
	if _, err := Login(context.Background(), o); err == nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestNormalizeInputs(t *testing.T) {
	if email, err := NormalizeEmail(" Owner@Example.COM "); err != nil || email != "owner@example.com" {
		t.Fatalf("email=%q err=%v", email, err)
	}
	for _, raw := range []string{"Name <owner@example.com>", "owner@example.com\r\nBcc: x@y.com", "invalid", "a b@example.com"} {
		if _, err := NormalizeEmail(raw); err == nil {
			t.Errorf("accepted email %q", raw)
		}
	}
}

func TestMetaSessionHandoffKeepsCredentialsOnTheirOrigins(t *testing.T) {
	f := &loginFixture{t: t}
	o := fixtureOptions(f)
	o.GetOTP = func(context.Context, time.Time) (string, error) { return "123456", nil }
	handoffs := 0
	o.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/auth/native/confirm-otp" {
			resp, err := f.transport(r)
			resp.Body = io.NopCloser(strings.NewReader(`{"registration_state":"logged_in","auth_meta_session":{"frl_access_token":"meta-token"}}`))
			return resp, err
		}
		if r.URL.Host == "auth.meta.com" {
			handoffs++
			if r.Header.Get("Cookie") != "" || r.Header.Get("X-Hatch-CSRF-Token") != "" || r.Header.Get("X-Hatch-Waterfall-Id") != "" {
				t.Error("Muse credentials leaked to Meta")
			}
			body, _ := io.ReadAll(r.Body)
			if string(body) != "frl_access_token=meta-token" || r.Method != "POST" {
				t.Errorf("unexpected handoff request")
			}
			return reply(r, 302, "", http.Header{"Location": {"https://muse.ai/"}, "Set-Cookie": {"meta_session=private-meta; Path=/; Secure; HttpOnly"}}), nil
		}
		if strings.Contains(r.Header.Get("Cookie"), "private-meta") {
			t.Error("Meta cookie leaked to Muse")
		}
		return f.transport(r)
	})
	result, err := Login(context.Background(), o)
	if err != nil || result == nil || handoffs != 1 {
		t.Fatalf("handoffs=%d err=%v", handoffs, err)
	}
	if result.Cookies["meta_session"] != "" {
		t.Fatal("Meta cookie exported as Muse cookie")
	}
}

func TestHomeNavigationRejectsExternalOrigin(t *testing.T) {
	calls := 0
	o := Options{Email: "owner@example.com", Proxy: "direct", GetOTP: func(context.Context, time.Time) (string, error) {
		t.Fatal("OTP requested after invalid navigation")
		return "", nil
	}, Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		return reply(r, 302, "", http.Header{"Location": {"https://evil.example/collect?token=do-not-log"}}), nil
	})}
	_, err := Login(context.Background(), o)
	if !errors.Is(err, ErrManualIntervention) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	if strings.Contains(err.Error(), "do-not-log") {
		t.Fatal("redirect secret leaked")
	}
}
