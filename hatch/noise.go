// Package hatch speaks muse.ai's Hatch gateway protocol: a WebSocket carrying
// a Noise_XX_25519_AESGCM_SHA256 channel, over which HTTP-like requests are
// multiplexed as protobuf frames.
package hatch

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const noiseProtocol = "Noise_XX_25519_AESGCM_SHA256"

// CipherState is one direction of the transport (or the handshake cipher).
type CipherState struct {
	aead cipher.AEAD
	n    uint64
}

func (c *CipherState) init(key []byte) {
	block, _ := aes.NewCipher(key)
	c.aead, _ = cipher.NewGCM(block)
	c.n = 0
}

func (c *CipherState) nonce() []byte {
	var nb [12]byte
	binary.BigEndian.PutUint64(nb[4:], c.n) // 4 zero bytes + 64-bit big-endian counter
	return nb[:]
}

func (c *CipherState) Encrypt(ad, plaintext []byte) []byte {
	if c.aead == nil {
		return append([]byte(nil), plaintext...)
	}
	out := c.aead.Seal(nil, c.nonce(), plaintext, ad)
	c.n++
	return out
}

func (c *CipherState) Decrypt(ad, ciphertext []byte) ([]byte, error) {
	if c.aead == nil {
		return append([]byte(nil), ciphertext...), nil
	}
	out, err := c.aead.Open(nil, c.nonce(), ciphertext, ad)
	if err != nil {
		return nil, errors.New("noise: decryption failed")
	}
	c.n++
	return out, nil
}

func hmacSHA256(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

func hkdf2(ck, ikm []byte) ([]byte, []byte) {
	temp := hmacSHA256(ck, ikm)
	o1 := hmacSHA256(temp, []byte{1})
	o2 := hmacSHA256(temp, o1, []byte{2})
	return o1, o2
}

type symmetricState struct {
	h, ck []byte
	cs    CipherState
}

func (s *symmetricState) mixHash(data []byte) {
	h := sha256.New()
	h.Write(s.h)
	h.Write(data)
	s.h = h.Sum(nil)
}

func (s *symmetricState) mixKey(ikm []byte) {
	var k []byte
	s.ck, k = hkdf2(s.ck, ikm)
	s.cs.init(k)
}

func (s *symmetricState) encryptAndHash(p []byte) []byte {
	c := s.cs.Encrypt(s.h, p)
	s.mixHash(c)
	return c
}

func (s *symmetricState) decryptAndHash(c []byte) ([]byte, error) {
	p, err := s.cs.Decrypt(s.h, c)
	if err != nil {
		return nil, err
	}
	s.mixHash(c)
	return p, nil
}

// XX message patterns.
var xxPattern = [][]string{{"e"}, {"e", "ee", "s", "es"}, {"s", "se"}}

// Handshake runs the XX pattern for one side.
type Handshake struct {
	initiator bool
	ss        symmetricState
	s, e      *ecdh.PrivateKey
	rs, re    []byte
	msg       int
}

// NewHandshake prepares an XX handshake. Keys may be nil (generated on use);
// tests pass fixed keys to replay the official vectors.
func NewHandshake(initiator bool, prologue []byte, static, ephemeral *ecdh.PrivateKey) *Handshake {
	h := &Handshake{initiator: initiator, s: static, e: ephemeral}
	name := []byte(noiseProtocol)
	if len(name) <= 32 {
		pad := make([]byte, 32)
		copy(pad, name)
		name = pad
	} else {
		sum := sha256.Sum256(name)
		name = sum[:]
	}
	h.ss.h = append([]byte(nil), name...)
	h.ss.ck = append([]byte(nil), name...)
	h.ss.mixHash(prologue)
	return h
}

func (h *Handshake) dh(priv *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("noise: missing local key")
	}
	pk, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pk)
}

func (h *Handshake) myTurn() bool { return (h.msg%2 == 0) == h.initiator }

// Done reports whether all three messages have been processed.
func (h *Handshake) Done() bool { return h.msg >= len(xxPattern) }

func (h *Handshake) mixDH(tok string) error {
	var priv *ecdh.PrivateKey
	var pub []byte
	switch tok {
	case "ee":
		priv, pub = h.e, h.re
	case "es":
		if h.initiator {
			priv, pub = h.e, h.rs
		} else {
			priv, pub = h.s, h.re
		}
	case "se":
		if h.initiator {
			priv, pub = h.s, h.re
		} else {
			priv, pub = h.e, h.rs
		}
	}
	shared, err := h.dh(priv, pub)
	if err != nil {
		return err
	}
	h.ss.mixKey(shared)
	return nil
}

func (h *Handshake) WriteMessage(payload []byte) ([]byte, error) {
	if h.Done() || !h.myTurn() {
		return nil, errors.New("noise: not our turn to write")
	}
	var out []byte
	for _, tok := range xxPattern[h.msg] {
		switch tok {
		case "e":
			if h.e == nil {
				k, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					return nil, err
				}
				h.e = k
			}
			pub := h.e.PublicKey().Bytes()
			out = append(out, pub...)
			h.ss.mixHash(pub)
		case "s":
			if h.s == nil {
				k, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					return nil, err
				}
				h.s = k
			}
			out = append(out, h.ss.encryptAndHash(h.s.PublicKey().Bytes())...)
		default:
			if err := h.mixDH(tok); err != nil {
				return nil, err
			}
		}
	}
	out = append(out, h.ss.encryptAndHash(payload)...)
	h.msg++
	return out, nil
}

func (h *Handshake) ReadMessage(msg []byte) ([]byte, error) {
	if h.Done() || h.myTurn() {
		return nil, errors.New("noise: not our turn to read")
	}
	for _, tok := range xxPattern[h.msg] {
		switch tok {
		case "e":
			if len(msg) < 32 {
				return nil, errors.New("noise: message too short")
			}
			h.re = append([]byte(nil), msg[:32]...)
			msg = msg[32:]
			h.ss.mixHash(h.re)
		case "s":
			n := 32
			if h.ss.cs.aead != nil {
				n += 16
			}
			if len(msg) < n {
				return nil, errors.New("noise: message too short")
			}
			rs, err := h.ss.decryptAndHash(msg[:n])
			if err != nil {
				return nil, err
			}
			h.rs, msg = rs, msg[n:]
		default:
			if err := h.mixDH(tok); err != nil {
				return nil, err
			}
		}
	}
	payload, err := h.ss.decryptAndHash(msg)
	if err != nil {
		return nil, err
	}
	h.msg++
	return payload, nil
}

// Split returns the transport ciphers (initiator→responder, responder→initiator).
func (h *Handshake) Split() (*CipherState, *CipherState) {
	k1, k2 := hkdf2(h.ss.ck, nil)
	c1, c2 := &CipherState{}, &CipherState{}
	c1.init(k1)
	c2.init(k2)
	return c1, c2
}

func (h *Handshake) HandshakeHash() []byte { return append([]byte(nil), h.ss.h...) }
func (h *Handshake) RemoteStatic() []byte  { return h.rs }
