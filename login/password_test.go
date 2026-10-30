package login

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Decrypt independently as the recipient: authenticate the anonymous sealed
// key, then restore the GCM ciphertext/tag ordering and authenticate its AAD.
func openPasswordEnvelope(encoded string, publicKey, privateKey *[32]byte, keyID byte, aadOverride string) (string, int64, error) {
	parts := strings.Split(encoded, ":")
	if len(parts) != 4 || parts[0] != "#PWD_BROWSER" || parts[1] != "5" {
		return "", 0, errors.New("invalid envelope format")
	}
	stamp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", 0, errors.New("invalid timestamp")
	}
	data, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(data) < 4 || data[0] != 1 || data[1] != keyID {
		return "", 0, errors.New("invalid envelope header")
	}
	sealedLen := int(binary.LittleEndian.Uint16(data[2:4]))
	if sealedLen != 80 || len(data) < 4+sealedLen+16 {
		return "", 0, errors.New("invalid sealed key length")
	}
	key, ok := box.OpenAnonymous(nil, data[4:4+sealedLen], publicKey, privateKey)
	if !ok || len(key) != 32 {
		return "", 0, errors.New("sealed key authentication failed")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", 0, err
	}
	tagAt := 4 + sealedLen
	ciphertext := append([]byte(nil), data[tagAt+16:]...)
	ciphertext = append(ciphertext, data[tagAt:tagAt+16]...)
	aad := parts[2]
	if aadOverride != "" {
		aad = aadOverride
	}
	plain, err := gcm.Open(nil, make([]byte, 12), ciphertext, []byte(aad))
	defer clear(plain)
	return string(plain), stamp, err
}

func TestPasswordEnvelopeRecipientDecryptsAndAuthenticates(t *testing.T) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1760000000, 0)
	password := "  p@ss:密码 🔐  "
	for _, encoding := range []string{"hex", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			raw := hex.EncodeToString(publicKey[:])
			if encoding == "base64" {
				raw = base64.StdEncoding.EncodeToString(publicKey[:])
			}
			key, err := readPasswordEncryption(map[string]any{"password_encryption": map[string]any{"key_id": float64(243), "public_key": raw}})
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := encryptPassword(password, key, now)
			if err != nil {
				t.Fatal(err)
			}
			plain, stamp, err := openPasswordEnvelope(encrypted, publicKey, privateKey, 243, "")
			if err != nil || plain != password || stamp != now.Unix() {
				t.Fatalf("recipient decryption failed: %v", err)
			}
			if _, _, err := openPasswordEnvelope(encrypted, publicKey, privateKey, 243, "1760000001"); err == nil {
				t.Fatal("modified timestamp AAD was accepted")
			}
			if _, _, err := openPasswordEnvelope(encrypted, publicKey, privateKey, 242, ""); err == nil {
				t.Fatal("wrong key ID was accepted")
			}
			second, err := encryptPassword(password, key, now)
			if err != nil || second == encrypted {
				t.Fatal("password encryption did not use fresh randomness")
			}
		})
	}
}

type passwordFixture struct {
	base                  *loginFixture
	publicKey, privateKey *[32]byte
	password              string
	flowState             string
	contact               map[string]any
	confirmation          map[string]any
	confirmationStatus    int
	missingKey            bool
	transportError        bool
	starts, confirms      int
	paths                 []string
}

func newPasswordFixture(t *testing.T) (*passwordFixture, Options) {
	t.Helper()
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &passwordFixture{
		base: &loginFixture{t: t}, publicKey: publicKey, privateKey: privateKey,
		password: "  private-password-勿回显  ", flowState: "started",
		contact:      map[string]any{"registration_state": "password_required", "csrf_token": "rotated-csrf", "contact_point": "owner@example.com"},
		confirmation: map[string]any{"registration_state": "logged_in"}, confirmationStatus: 200,
	}
	o := fixtureOptions(f.base)
	o.GetOTP, o.Password, o.Region = nil, f.password, "jp"
	o.Transport = roundTripFunc(f.transport)
	return f, o
}

func (f *passwordFixture) transport(r *http.Request) (*http.Response, error) {
	f.paths = append(f.paths, r.URL.Path)
	t := f.base.t
	if r.URL.Host != "muse.ai" {
		t.Errorf("unexpected password-login origin: %s", r.URL.Host)
	}
	respond := func(status int, value map[string]any, headers http.Header) *http.Response {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal("could not marshal mock response")
		}
		return reply(r, status, string(data), headers)
	}
	switch r.URL.Path {
	case "/api/auth/native/restart", "/api/auth/native/start":
		flow := f.flowState
		if r.URL.Path == "/api/auth/native/start" {
			f.starts++
			flow = "started"
			if r.Header.Get("X-Hatch-CSRF-Token") != "secret-csrf" {
				t.Error("start lacks the restart CSRF token")
			}
		}
		body := map[string]any{"flow_state": flow, "csrf_token": "secret-csrf"}
		if r.URL.Path == "/api/auth/native/start" {
			body["csrf_token"] = "unused-start-csrf"
		}
		if !f.missingKey && flow == "started" {
			body["password_encryption"] = map[string]any{"key_id": 7, "public_key": hex.EncodeToString(f.publicKey[:])}
		}
		return respond(200, body, http.Header{"Set-Cookie": {"native_state=state; Path=/; Secure; HttpOnly"}}), nil
	case "/api/auth/native/send-otp":
		// Reuse the OTP fixture's contact/CSRF/cookie checks, but do not fetch
		// an inbox or use any code that this initialization may have sent.
		response, err := f.base.transport(r)
		if err != nil {
			return nil, err
		}
		_ = response.Body.Close()
		return respond(200, f.contact, nil), nil
	case "/api/auth/native/confirm-password":
		f.confirms++
		if r.Method != http.MethodPost || r.Header.Get("X-Hatch-CSRF-Token") != "rotated-csrf" || r.Header.Get("X-Hatch-Waterfall-Id") == "" {
			t.Error("password confirmation lacks native authentication headers")
		}
		cookie, err := r.Cookie("native_state")
		if err != nil || cookie.Value != "state" {
			t.Error("password confirmation lost its isolated session")
		}
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), f.password) {
			t.Error("plaintext password sent")
		}
		var body map[string]any
		if json.Unmarshal(raw, &body) != nil || len(body) != 2 || body["return_to"] != "/" {
			t.Fatal("unexpected password confirmation fields")
		}
		plain, stamp, err := openPasswordEnvelope(stringValue(body, "password"), f.publicKey, f.privateKey, 7, "")
		if err != nil || plain != f.password || time.Since(time.Unix(stamp, 0)) > 5*time.Second {
			t.Errorf("password payload failed recipient verification: %v", err)
		}
		if f.transportError {
			return nil, errors.New("secret upstream body " + f.password)
		}
		headers := http.Header{}
		if !f.base.missingSession {
			headers.Add("Set-Cookie", "hatch_sess=password-session; Path=/; Max-Age=3600; Secure; HttpOnly")
		}
		return respond(f.confirmationStatus, f.confirmation, headers), nil
	}
	return f.base.transport(r)
}

func TestPasswordLoginUsesOneConfirmationWithoutReadingOTP(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		flag        any
		setFlag     bool
	}{
		{"password required", "password_required", nil, false},
		{"password required overrides flag", "password_required", false, true},
		{"OTP with password available", "otp_sent", true, true},
		{"OTP with missing flag", "otp_sent", nil, false},
		{"OTP with null flag", "otp_sent", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, o := newPasswordFixture(t)
			f.flowState = "new"
			f.contact["registration_state"] = tc.state
			if tc.setFlag {
				f.contact["password_login_available"] = tc.flag
			}
			var phases []string
			o.OnStage = func(phase string) { phases = append(phases, phase) }
			result, err := Login(context.Background(), o)
			if err != nil || result == nil || !result.IdentityVerified || result.Email != "owner@example.com" || result.Cookies["hatch_sess"] != "password-session" {
				t.Fatalf("password login failed: %v", err)
			}
			if f.starts != 1 || f.base.sends != 1 || f.confirms != 1 || f.base.authChecks != 1 || f.base.confirms != 0 {
				t.Fatal("unexpected password or OTP execution count")
			}
			if strings.Join(phases, ",") != "initializing,checking_account,encrypting_password,confirming_password,verifying,completed" {
				t.Fatalf("unexpected phases: %v", phases)
			}
		})
	}
}

func TestPasswordLoginRefusesUnsupportedAndManualStates(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(*passwordFixture)
		code     string
		confirms int
	}{
		{"unavailable", func(f *passwordFixture) {
			f.contact["registration_state"] = "otp_sent"
			f.contact["password_login_available"] = false
		}, "password_unavailable", 0},
		{"unknown state", func(f *passwordFixture) { f.contact["registration_state"] = "unknown_state" }, "password_state_unrecognized", 0},
		{"missing state", func(f *passwordFixture) { delete(f.contact, "registration_state") }, "password_state_unrecognized", 0},
		{"empty state", func(f *passwordFixture) { f.contact["registration_state"] = "" }, "password_state_unrecognized", 0},
		{"null state", func(f *passwordFixture) { f.contact["registration_state"] = nil }, "password_state_unrecognized", 0},
		{"invalid state type", func(f *passwordFixture) { f.contact["registration_state"] = false }, "password_state_unrecognized", 0},
		{"unknown state with unavailable flag", func(f *passwordFixture) {
			f.contact["registration_state"] = "unknown_state"
			f.contact["password_login_available"] = false
		}, "password_state_unrecognized", 0},
		{"unknown state must not echo upstream", func(f *passwordFixture) {
			f.contact["registration_state"] = "unknown-" + f.password
		}, "password_state_unrecognized", 0},
		{"missing encryption", func(f *passwordFixture) { f.missingKey = true }, "password_encryption_unavailable", 0},
		{"contact mismatch", func(f *passwordFixture) { f.contact["contact_point"] = "someone@example.com" }, "identity_mismatch", 0},
		{"final identity mismatch", func(f *passwordFixture) { f.base.mismatch = true }, "identity_mismatch", 1},
		{"registration", func(f *passwordFixture) { f.contact["registration_state"] = "completion_required" }, "manual_intervention", 0},
		{"two factor", func(f *passwordFixture) { f.confirmation["registration_state"] = "two_factor_required" }, "manual_intervention", 1},
		{"requires OTP", func(f *passwordFixture) { f.confirmation["registration_state"] = "otp_required" }, "manual_intervention", 1},
		{"consent", func(f *passwordFixture) { f.confirmation["requires_consent"] = true }, "manual_intervention", 1},
		{"reactivation", func(f *passwordFixture) { f.confirmation["reactivation_required"] = true }, "manual_intervention", 1},
		{"account upsell", func(f *passwordFixture) { f.confirmation["registration_state"] = "ntp_upsell" }, "manual_intervention", 1},
		{"expired flow", func(f *passwordFixture) { f.flowState = "completion_required" }, "manual_intervention", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, o := newPasswordFixture(t)
			tc.mutate(f)
			result, err := Login(context.Background(), o)
			var loginErr *Error
			if result != nil || !errors.As(err, &loginErr) || loginErr.Code != tc.code {
				t.Fatalf("unexpected error: %v", err)
			}
			if f.confirms != tc.confirms || f.base.confirms != 0 {
				t.Fatal("password mode retried or consumed OTP")
			}
			if tc.code == "password_state_unrecognized" && (loginErr.Stage != "checking_account" || err.Error() != "登录服务返回了未识别的账号状态，未提交密码") {
				t.Fatal("unrecognized state was not safely classified at account initialization")
			}
			if tc.code == "password_unavailable" && err.Error() != "此账号当前未开放密码登录，请使用邮箱验证码" {
				t.Fatal("explicit password unavailability was not distinguished")
			}
			if strings.Contains(err.Error(), f.password) || strings.Contains(err.Error(), "unknown_state") {
				t.Fatal("login error exposed an upstream value")
			}
			if tc.code == "manual_intervention" && !errors.Is(err, ErrManualIntervention) {
				t.Fatal("manual intervention error was not classified")
			}
		})
	}
}

func TestPasswordLoginCancellationAndSecretErrors(t *testing.T) {
	for _, cancelAt := range []string{"checking_account", "confirming_password"} {
		t.Run("cancel at "+cancelAt, func(t *testing.T) {
			f, o := newPasswordFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			o.OnStage = func(stage string) {
				if stage == cancelAt {
					cancel()
				}
			}
			if _, err := Login(ctx, o); !errors.Is(err, context.Canceled) || f.confirms != 0 {
				t.Fatalf("confirmation sent after cancellation: %v", err)
			}
			if cancelAt == "checking_account" && f.base.sends != 0 {
				t.Fatal("contact initialization sent after cancellation")
			}
		})
	}
	for _, transportError := range []bool{false, true} {
		t.Run(strconv.FormatBool(transportError), func(t *testing.T) {
			f, o := newPasswordFixture(t)
			f.transportError = transportError
			f.confirmationStatus = http.StatusBadRequest
			f.confirmation = map[string]any{"type": "invalidPassword", "detail": f.password}
			_, err := Login(context.Background(), o)
			if err == nil || strings.Contains(err.Error(), f.password) || strings.Contains(err.Error(), "upstream body") {
				t.Fatal("password error was missing or exposed a secret")
			}
			if f.confirms != 1 || f.base.sends != 1 || f.base.confirms != 0 {
				t.Fatal("failed password attempt retried or fell back to OTP")
			}
		})
	}
}

func TestPasswordOptionsAndEncryptionValidation(t *testing.T) {
	f, o := newPasswordFixture(t)
	if err := ValidateOptions(o); err != nil {
		t.Fatal(err)
	}
	o.GetOTP = func(context.Context, time.Time) (string, error) { return "123456", nil }
	if err := ValidateOptions(o); err == nil {
		t.Fatal("password accepted with manual OTP mode")
	}
	o.GetOTP = nil
	o.Password = strings.Repeat("a", 4097)
	if err := ValidateOptions(o); err == nil {
		t.Fatal("unbounded password accepted")
	}
	for _, id := range []any{nil, "7", float64(-1), float64(256), 1.5} {
		_, err := readPasswordEncryption(map[string]any{"password_encryption": map[string]any{"key_id": id, "public_key": hex.EncodeToString(f.publicKey[:])}})
		if err == nil {
			t.Fatal("invalid encryption key ID accepted")
		}
	}
	for _, key := range []string{"", "not-base64", hex.EncodeToString(f.publicKey[:31])} {
		_, err := readPasswordEncryption(map[string]any{"password_encryption": map[string]any{"key_id": float64(7), "public_key": key}})
		if err == nil {
			t.Fatal("invalid encryption public key accepted")
		}
	}
}
