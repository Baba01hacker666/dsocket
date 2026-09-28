package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// HKDF implements standard RFC 5869 HKDF using SHA-256.
func HKDFExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

func HKDFExpand(prk, info []byte, length int) ([]byte, error) {
	hashLen := sha256.Size
	n := (length + hashLen - 1) / hashLen
	if n > 255 {
		return nil, fmt.Errorf("hkdf: requested output length too long")
	}

	okm := make([]byte, 0, n*hashLen)
	var prev []byte
	for i := 1; i <= n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length], nil
}

// DeriveRendezvousID derives a public session ID from a shared secret.
// The relay server sees only this ID and cannot infer the original secret.
func DeriveRendezvousID(secret string) []byte {
	h := hmac.New(sha256.New, []byte("dsocket-rendezvous-v1"))
	h.Write([]byte(secret))
	return h.Sum(nil)
}

// SessionKeys holds derived symmetric keys and parameters for full-duplex E2EE.
type SessionKeys struct {
	KeySend   []byte // 32 bytes AES key
	KeyRecv   []byte // 32 bytes AES key
	AuthSend  []byte // 32 bytes HMAC auth key
	AuthRecv  []byte // 32 bytes HMAC auth key
	NonceSend [4]byte
	NonceRecv [4]byte
}

// DeriveSessionKeys derives bidirectional session keys and verification tags.
// isHost is true for the listening peer (Peer A), false for the connecting peer (Peer B).
func DeriveSessionKeys(secret string, saltHost, saltJoin []byte, isHost bool) (*SessionKeys, error) {
	// Base secret material
	hMaster := hmac.New(sha256.New, []byte("dsocket-master-key-v1"))
	hMaster.Write([]byte(secret))
	masterIKM := hMaster.Sum(nil)

	// Combine salts
	combinedSalt := append(append([]byte{}, saltHost...), saltJoin...)
	prk := HKDFExtract(combinedSalt, masterIKM)

	// We need:
	// Key_HJ: 32 bytes (Host -> Joiner AES-256)
	// Key_JH: 32 bytes (Joiner -> Host AES-256)
	// Auth_HJ: 32 bytes (Host auth tag key)
	// Auth_JH: 32 bytes (Joiner auth tag key)
	// Nonce_HJ: 4 bytes base nonce
	// Nonce_JH: 4 bytes base nonce
	// Total = 32 + 32 + 32 + 32 + 4 + 4 = 136 bytes
	okm, err := HKDFExpand(prk, []byte("dsocket-e2ee-session-keys-v1"), 136)
	if err != nil {
		return nil, err
	}

	keyHJ := okm[0:32]
	keyJH := okm[32:64]
	authHJ := okm[64:96]
	authJH := okm[96:128]
	nonceHJ := okm[128:132]
	nonceJH := okm[132:136]

	sk := &SessionKeys{}
	if isHost {
		sk.KeySend = keyHJ
		sk.KeyRecv = keyJH
		sk.AuthSend = authHJ
		sk.AuthRecv = authJH
		copy(sk.NonceSend[:], nonceHJ)
		copy(sk.NonceRecv[:], nonceJH)
	} else {
		sk.KeySend = keyJH
		sk.KeyRecv = keyHJ
		sk.AuthSend = authJH
		sk.AuthRecv = authHJ
		copy(sk.NonceSend[:], nonceJH)
		copy(sk.NonceRecv[:], nonceHJ)
	}
	return sk, nil
}

// GenerateAuthToken creates an authentication confirmation token for handshake.
func GenerateAuthToken(authKey []byte, roleLabel string, peerSalt []byte) []byte {
	h := hmac.New(sha256.New, authKey)
	h.Write([]byte(roleLabel))
	h.Write(peerSalt)
	return h.Sum(nil)
}

// BuildNonce constructs a 12-byte nonce from a 4-byte base and 8-byte uint64 sequence.
func BuildNonce(base [4]byte, seq uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[0:4], base[:])
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}
