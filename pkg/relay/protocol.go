package relay

import (
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	MagicBytes = [4]byte{'D', 'S', 'K', 'T'}
)

const (
	ProtocolVersion byte = 0x01

	CmdHost byte = 0x01 // Register as session host / listener
	CmdJoin byte = 0x02 // Join an existing session host

	StatusWaiting byte = 0x10 // Host registered, waiting for joiner
	StatusMatched byte = 0x20 // Peer connected, stream bridged
	StatusBusy    byte = 0x30 // Session already has a host
	StatusTimeout byte = 0x40 // Wait timed out
	StatusError   byte = 0xFF // Protocol or internal error

	RendezvousIDSize = 32
	GreetingSize     = 4 + 1 + 1 + RendezvousIDSize // 38 bytes
)

var (
	ErrInvalidMagic   = errors.New("dsocket relay: invalid magic header")
	ErrInvalidVersion = errors.New("dsocket relay: unsupported protocol version")
	ErrSessionBusy    = errors.New("dsocket relay: session token is already in use")
	ErrSessionTimeout = errors.New("dsocket relay: timed out waiting for peer")
	ErrRelayRejected  = errors.New("dsocket relay: connection rejected by relay")
)

// Greeting is sent by client to relay upon initial connection.
type Greeting struct {
	Command      byte
	RendezvousID [RendezvousIDSize]byte
}

func (g *Greeting) Encode() []byte {
	buf := make([]byte, GreetingSize)
	copy(buf[0:4], MagicBytes[:])
	buf[4] = ProtocolVersion
	buf[5] = g.Command
	copy(buf[6:38], g.RendezvousID[:])
	return buf
}

func DecodeGreeting(b []byte) (*Greeting, error) {
	if len(b) < GreetingSize {
		return nil, errors.New("greeting buffer too short")
	}
	if b[0] != MagicBytes[0] || b[1] != MagicBytes[1] || b[2] != MagicBytes[2] || b[3] != MagicBytes[3] {
		return nil, ErrInvalidMagic
	}
	if b[4] != ProtocolVersion {
		return nil, ErrInvalidVersion
	}
	cmd := b[5]
	if cmd != CmdHost && cmd != CmdJoin {
		return nil, fmt.Errorf("invalid command: 0x%x", cmd)
	}

	var rID [RendezvousIDSize]byte
	copy(rID[:], b[6:38])

	return &Greeting{
		Command:      cmd,
		RendezvousID: rID,
	}, nil
}

func FormatID(id [RendezvousIDSize]byte) string {
	return hex.EncodeToString(id[:8]) + "..."
}
