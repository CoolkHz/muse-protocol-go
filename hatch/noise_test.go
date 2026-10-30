package hatch

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func key(s string) *ecdh.PrivateKey {
	k, err := ecdh.X25519().NewPrivateKey(mustHex(s))
	if err != nil {
		panic(err)
	}
	return k
}

// The official cacophony vector for Noise_XX_25519_AESGCM_SHA256.
func TestNoiseXXVector(t *testing.T) {
	prologue := mustHex("4a6f686e2047616c74")
	ini := NewHandshake(true, prologue,
		key("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"),
		key("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"))
	resp := NewHandshake(false, prologue,
		key("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"),
		key("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"))

	for i, m := range xxVectorMessages {
		payload, want := mustHex(m.payload), mustHex(m.ciphertext)
		var w, r *Handshake
		if i%2 == 0 {
			w, r = ini, resp
		} else {
			w, r = resp, ini
		}
		if i < 3 {
			got, err := w.WriteMessage(payload)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("message %d: err=%v\n got %x\nwant %x", i, err, got, want)
			}
			back, err := r.ReadMessage(got)
			if err != nil || !bytes.Equal(back, payload) {
				t.Fatalf("message %d read: %v", i, err)
			}
			if i == 2 {
				if hh := hex.EncodeToString(ini.HandshakeHash()); hh != "1b7aefb1125762aa21a252890d00af54519638b76437444538f9a52f21e2e0dc" {
					t.Fatalf("handshake hash %s", hh)
				}
			}
			continue
		}
		break
	}
	// Transport messages keep alternating: even indexes are sent by the initiator.
	iTx, iRx := ini.Split()
	rRx, rTx := resp.Split()
	for i, m := range xxVectorMessages[3:] {
		payload, want := mustHex(m.payload), mustHex(m.ciphertext)
		tx, rx := iTx, rRx
		if (i+3)%2 == 1 {
			tx, rx = rTx, iRx
		}
		got := tx.Encrypt(nil, payload)
		if !bytes.Equal(got, want) {
			t.Fatalf("transport %d:\n got %x\nwant %x", i, got, want)
		}
		if back, err := rx.Decrypt(nil, got); err != nil || !bytes.Equal(back, payload) {
			t.Fatalf("transport %d decrypt: %v", i, err)
		}
	}
}
