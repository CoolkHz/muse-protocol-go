package login

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
)

type passwordEncryption struct {
	keyID     byte
	publicKey [32]byte
}

func readPasswordEncryption(data map[string]any) (passwordEncryption, error) {
	var key passwordEncryption
	parameters, ok := data["password_encryption"].(map[string]any)
	if !ok {
		return key, errors.New("password_encryption_unavailable")
	}
	id, ok := parameters["key_id"].(float64)
	if !ok || math.IsNaN(id) || math.IsInf(id, 0) || id < 0 || id > 255 || math.Trunc(id) != id {
		return key, errors.New("password_encryption_unavailable")
	}
	raw := strings.TrimSpace(stringValue(parameters, "public_key"))
	var decoded []byte
	var err error
	if len(raw) == 64 {
		decoded, err = hex.DecodeString(raw)
	}
	if decoded == nil || err != nil {
		decoded, err = base64.StdEncoding.DecodeString(raw)
	}
	if err != nil || len(decoded) != len(key.publicKey) {
		return key, errors.New("password_encryption_unavailable")
	}
	key.keyID = byte(id)
	copy(key.publicKey[:], decoded)
	return key, nil
}

// encryptPassword reproduces Muse's public native-auth browser envelope. The
// AES key is fresh for every attempt, so the protocol's zero GCM nonce is never
// reused with the same key. SealAnonymous implements libsodium crypto_box_seal.
func encryptPassword(password string, key passwordEncryption, now time.Time) (string, error) {
	var aesKey [32]byte
	if _, err := rand.Read(aesKey[:]); err != nil {
		return "", errors.New("password_encryption_failed")
	}
	defer clear(aesKey[:])
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return "", errors.New("password_encryption_failed")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("password_encryption_failed")
	}
	stamp := strconv.FormatInt(now.Unix(), 10)
	plain := []byte(password)
	defer clear(plain)
	ciphertext := gcm.Seal(nil, make([]byte, gcm.NonceSize()), plain, []byte(stamp))
	sealedKey, err := box.SealAnonymous(nil, aesKey[:], &key.publicKey, rand.Reader)
	if err != nil || len(sealedKey) > math.MaxUint16 {
		return "", errors.New("password_encryption_failed")
	}
	// Browser order: version, key ID, sealed-key length (LE), sealed key,
	// authentication tag, ciphertext. Go's AEAD appends the tag instead.
	tagAt := len(ciphertext) - gcm.Overhead()
	envelope := make([]byte, 4, 4+len(sealedKey)+len(ciphertext))
	envelope[0], envelope[1] = 1, key.keyID
	binary.LittleEndian.PutUint16(envelope[2:4], uint16(len(sealedKey)))
	envelope = append(envelope, sealedKey...)
	envelope = append(envelope, ciphertext[tagAt:]...)
	envelope = append(envelope, ciphertext[:tagAt]...)
	return "#PWD_BROWSER:5:" + stamp + ":" + base64.StdEncoding.EncodeToString(envelope), nil
}

func (s *session) confirmPassword(ctx context.Context, o Options, restart *response) (*response, error) {
	defer func() { o.Password = "" }()
	if err := s.checkIdentity(restart.data); err != nil {
		return nil, err
	}
	bootstrap := restart
	switch stringValue(restart.data, "flow_state") {
	case "new":
		var err error
		bootstrap, err = s.request(ctx, "/api/auth/native/start", map[string]any{}, s.csrf)
		if err != nil {
			return nil, err
		}
		if err := s.requireSuccess(bootstrap); err != nil {
			return nil, err
		}
		if state := stringValue(bootstrap.data, "flow_state"); state != "" && state != "started" {
			return nil, s.manual()
		}
		// The browser replaces the encryption key after start but retains the
		// restart CSRF token, even if start includes a csrf_token field.
	case "started":
	default:
		return nil, s.manual()
	}
	if err := s.checkIdentity(bootstrap.data); err != nil {
		return nil, err
	}
	key, err := readPasswordEncryption(bootstrap.data)
	if err != nil {
		return nil, failure(s.phase, "password_encryption_unavailable", nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.stage("checking_account")
	payload := map[string]any{"contact_point": s.email}
	if o.Region != "" {
		payload["region"] = strings.ToUpper(o.Region)
	}
	// This is the front end's only contact-initialization operation. It may
	// send a code, but password mode never calls an inbox or OTP confirmation.
	contact, err := s.request(ctx, "/api/auth/native/send-otp", payload, s.csrf)
	if err != nil {
		return nil, err
	}
	state := stringValue(contact.data, "registration_state")
	checked := *contact
	if state == "password_required" {
		checked.data = maps.Clone(contact.data)
		delete(checked.data, "registration_state")
	}
	if err := s.requireSuccess(&checked); err != nil {
		return nil, err
	}
	if err := s.checkIdentity(contact.data); err != nil {
		return nil, err
	}
	available, supported := contact.data["password_login_available"].(bool)
	// The browser shows the password action unless availability is exactly
	// false. A password_required state enters that screen unconditionally.
	switch state {
	case "password_required":
	case "otp_sent":
		if supported && !available {
			return nil, failure(s.phase, "password_unavailable", nil)
		}
	default:
		// An unrecognized response is not evidence that this account lacks
		// password login. Do not submit a password or echo upstream state.
		return nil, failure(s.phase, "password_state_unrecognized", nil)
	}
	if csrf := stringValue(contact.data, "csrf_token"); csrf != "" {
		s.csrf = csrf
	}
	s.stage("encrypting_password")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	encrypted, err := encryptPassword(o.Password, key, time.Now())
	o.Password = ""
	if err != nil {
		return nil, failure(s.phase, "password_encryption_failed", nil)
	}
	s.stage("confirming_password")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.request(ctx, "/api/auth/native/confirm-password", map[string]any{"password": encrypted, "return_to": "/"}, s.csrf)
}
