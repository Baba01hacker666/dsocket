package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCryptoRoundtrip(t *testing.T) {
	secret := "correct-horse-battery-staple-super-secret"
	saltHost := make([]byte, 32)
	saltJoin := make([]byte, 32)
	rand.Read(saltHost)
	rand.Read(saltJoin)

	keysHost, err := DeriveSessionKeys(secret, saltHost, saltJoin, true)
	if err != nil {
		t.Fatalf("DeriveSessionKeys host failed: %v", err)
	}

	keysJoin, err := DeriveSessionKeys(secret, saltHost, saltJoin, false)
	if err != nil {
		t.Fatalf("DeriveSessionKeys join failed: %v", err)
	}

	// Verify key matching
	if !bytes.Equal(keysHost.KeySend, keysJoin.KeyRecv) {
		t.Fatalf("Host KeySend != Join KeyRecv")
	}
	if !bytes.Equal(keysHost.KeyRecv, keysJoin.KeySend) {
		t.Fatalf("Host KeyRecv != Join KeySend")
	}

	// Test auth tokens
	hostToken := GenerateAuthToken(keysHost.AuthSend, "DSOCKET-V1-HOST-AUTH", saltJoin)
	joinTokenExpected := GenerateAuthToken(keysJoin.AuthRecv, "DSOCKET-V1-HOST-AUTH", saltJoin)
	if !bytes.Equal(hostToken, joinTokenExpected) {
		t.Fatalf("Host auth token mismatch")
	}

	// Test Frame Encryption / Decryption
	seq := uint64(0)
	nonceHost := BuildNonce(keysHost.NonceSend, seq)
	nonceJoin := BuildNonce(keysJoin.NonceRecv, seq)
	if nonceHost != nonceJoin {
		t.Fatalf("Nonces do not match")
	}

	msg := []byte("Hello, this is a secure end-to-end encrypted packet!")
	frame, err := EncryptFrame(keysHost.KeySend, nonceHost, seq, msg)
	if err != nil {
		t.Fatalf("EncryptFrame failed: %v", err)
	}

	// Strip 2-byte header
	payload := frame[2:]
	decrypted, err := DecryptFrame(keysJoin.KeyRecv, nonceJoin, seq, payload)
	if err != nil {
		t.Fatalf("DecryptFrame failed: %v", err)
	}

	if !bytes.Equal(msg, decrypted) {
		t.Fatalf("Decrypted message does not match original")
	}

	// Test tampering detection
	payload[len(payload)-1] ^= 0x01
	_, err = DecryptFrame(keysJoin.KeyRecv, nonceJoin, seq, payload)
	if err == nil {
		t.Fatalf("Expected tamper detection error, got nil")
	}
}
