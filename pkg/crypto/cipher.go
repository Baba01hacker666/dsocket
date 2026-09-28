package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrDecryptionFailed = errors.New("dsocket: decryption failed or data tampered")
	ErrFrameTooLarge    = errors.New("dsocket: frame exceeds maximum allowed size")
)

const (
	MaxPlaintextSize = 32 * 1024 // 32 KB chunk size
	GCMTagSize       = 16
	HeaderSize       = 2 // 2-byte uint16 length
)

// EncryptFrame encrypts plaintext with AES-256-GCM using key and sequence nonce.
// It returns a wire frame: [2 bytes Length] [Ciphertext + Tag].
// Additional Authenticated Data (AAD) binds the sequence number and length.
func EncryptFrame(key []byte, nonce [12]byte, seq uint64, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrFrameTooLarge
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Total wire length = 2 (header) + len(plaintext) + 16 (tag)
	payloadLen := len(plaintext) + GCMTagSize
	frame := make([]byte, HeaderSize+payloadLen)
	binary.BigEndian.PutUint16(frame[0:2], uint16(payloadLen))

	// AAD binds length (2 bytes) + sequence number (8 bytes)
	var aad [10]byte
	binary.BigEndian.PutUint16(aad[0:2], uint16(payloadLen))
	binary.BigEndian.PutUint64(aad[2:10], seq)

	// Encrypt in-place into frame[2:]
	gcm.Seal(frame[2:2], nonce[:], plaintext, aad[:])

	return frame, nil
}

// DecryptFrame decrypts an AES-256-GCM payload using key and sequence nonce.
// payload must be [Ciphertext + Tag].
func DecryptFrame(key []byte, nonce [12]byte, seq uint64, payload []byte) ([]byte, error) {
	if len(payload) < GCMTagSize {
		return nil, ErrDecryptionFailed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var aad [10]byte
	binary.BigEndian.PutUint16(aad[0:2], uint16(len(payload)))
	binary.BigEndian.PutUint64(aad[2:10], seq)

	plaintext, err := gcm.Open(nil, nonce[:], payload, aad[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}
