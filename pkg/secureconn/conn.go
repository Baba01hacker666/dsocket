package secureconn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"dsocket/pkg/crypto"
)

var (
	ErrHandshakeFailed = errors.New("dsocket: handshake authentication failed (wrong secret or MITM)")
	ErrConnClosed      = errors.New("dsocket: secure connection closed")
)

const (
	SaltSize = 32
	AuthSize = 32
)

// Conn wraps a net.Conn with authenticated, sequence-tracked end-to-end encryption.
type Conn struct {
	raw net.Conn

	keys   *crypto.SessionKeys
	isHost bool

	sendSeq  uint64
	sendLock sync.Mutex

	recvSeq  uint64
	recvLock sync.Mutex

	readBuf    []byte
	readBufPtr int

	closed   bool
	closeErr error
	closeMu  sync.Mutex
}

// Handshake performs mutual authenticated key exchange over rawConn.
// If isHost is true, this endpoint acts as the listener/peer A.
// If isHost is false, this endpoint acts as the dialer/peer B.
func Handshake(rawConn net.Conn, secret string, isHost bool) (*Conn, error) {
	mySalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, mySalt); err != nil {
		return nil, fmt.Errorf("failed to generate local salt: %w", err)
	}

	peerSalt := make([]byte, SaltSize)

	// Exchange salts
	if isHost {
		// Host sends salt first, then reads joiner salt
		if _, err := rawConn.Write(mySalt); err != nil {
			return nil, fmt.Errorf("failed to send host salt: %w", err)
		}
		if _, err := io.ReadFull(rawConn, peerSalt); err != nil {
			return nil, fmt.Errorf("failed to read joiner salt: %w", err)
		}
	} else {
		// Joiner reads host salt first, then sends joiner salt
		if _, err := io.ReadFull(rawConn, peerSalt); err != nil {
			return nil, fmt.Errorf("failed to read host salt: %w", err)
		}
		if _, err := rawConn.Write(mySalt); err != nil {
			return nil, fmt.Errorf("failed to send joiner salt: %w", err)
		}
	}

	saltHost := mySalt
	saltJoin := peerSalt
	if !isHost {
		saltHost = peerSalt
		saltJoin = mySalt
	}

	// Derive session keys
	keys, err := crypto.DeriveSessionKeys(secret, saltHost, saltJoin, isHost)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Mutual authentication check
	myRoleLabel := "DSOCKET-V1-HOST-AUTH"
	peerRoleLabel := "DSOCKET-V1-JOIN-AUTH"
	if !isHost {
		myRoleLabel = "DSOCKET-V1-JOIN-AUTH"
		peerRoleLabel = "DSOCKET-V1-HOST-AUTH"
	}

	myAuthToken := crypto.GenerateAuthToken(keys.AuthSend, myRoleLabel, peerSalt)
	peerAuthTokenExpected := crypto.GenerateAuthToken(keys.AuthRecv, peerRoleLabel, mySalt)

	peerAuthToken := make([]byte, AuthSize)

	if isHost {
		if _, err := rawConn.Write(myAuthToken); err != nil {
			return nil, fmt.Errorf("failed to send auth token: %w", err)
		}
		if _, err := io.ReadFull(rawConn, peerAuthToken); err != nil {
			return nil, fmt.Errorf("failed to read peer auth token: %w", err)
		}
	} else {
		if _, err := io.ReadFull(rawConn, peerAuthToken); err != nil {
			return nil, fmt.Errorf("failed to read peer auth token: %w", err)
		}
		if _, err := rawConn.Write(myAuthToken); err != nil {
			return nil, fmt.Errorf("failed to send auth token: %w", err)
		}
	}

	if subtle.ConstantTimeCompare(peerAuthToken, peerAuthTokenExpected) != 1 {
		rawConn.Close()
		return nil, ErrHandshakeFailed
	}

	return &Conn{
		raw:    rawConn,
		keys:   keys,
		isHost: isHost,
	}, nil
}

// Read reads decrypted plaintext bytes into p.
func (c *Conn) Read(p []byte) (int, error) {
	c.recvLock.Lock()
	defer c.recvLock.Unlock()

	// Drain any leftover buffered plaintext from previous frame
	if c.readBufPtr < len(c.readBuf) {
		n := copy(p, c.readBuf[c.readBufPtr:])
		c.readBufPtr += n
		if c.readBufPtr >= len(c.readBuf) {
			c.readBuf = nil
			c.readBufPtr = 0
		}
		return n, nil
	}

	// Read next frame length header (2 bytes)
	var hdr [2]byte
	if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
		return 0, err
	}

	payloadLen := int(binary.BigEndian.Uint16(hdr[:]))
	if payloadLen < crypto.GCMTagSize || payloadLen > crypto.MaxPlaintextSize+crypto.GCMTagSize {
		return 0, fmt.Errorf("invalid frame payload length: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.raw, payload); err != nil {
		return 0, err
	}

	nonce := crypto.BuildNonce(c.keys.NonceRecv, c.recvSeq)
	c.recvSeq++

	plaintext, err := crypto.DecryptFrame(c.keys.KeyRecv, nonce, c.recvSeq-1, payload)
	if err != nil {
		return 0, err
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		// Buffer remainder for next call
		c.readBuf = plaintext
		c.readBufPtr = n
	}

	return n, nil
}

// Write encrypts and sends p as one or more authenticated frames.
func (c *Conn) Write(p []byte) (int, error) {
	c.sendLock.Lock()
	defer c.sendLock.Unlock()

	totalSent := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > crypto.MaxPlaintextSize {
			chunkSize = crypto.MaxPlaintextSize
		}

		chunk := p[:chunkSize]
		p = p[chunkSize:]

		nonce := crypto.BuildNonce(c.keys.NonceSend, c.sendSeq)
		seq := c.sendSeq
		c.sendSeq++

		frame, err := crypto.EncryptFrame(c.keys.KeySend, nonce, seq, chunk)
		if err != nil {
			return totalSent, err
		}

		if _, err := c.raw.Write(frame); err != nil {
			return totalSent, err
		}

		totalSent += chunkSize
	}

	return totalSent, nil
}

// Close closes the underlying network connection.
func (c *Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.raw.Close()
}

func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
