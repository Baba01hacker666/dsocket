package relay

import (
	"fmt"
	"io"
	"net"
	"time"
)

// Connect connects to the dsocket rendezvous relay server.
// If isHost is true, it registers as the waiting peer (host).
// If isHost is false, it connects to an existing host (joiner).
func Connect(relayAddr string, rendezvousID []byte, isHost bool, timeout time.Duration) (net.Conn, error) {
	if len(rendezvousID) != RendezvousIDSize {
		return nil, fmt.Errorf("invalid rendezvous ID size: expected %d, got %d", RendezvousIDSize, len(rendezvousID))
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial relay %s: %w", relayAddr, err)
	}

	var rID [RendezvousIDSize]byte
	copy(rID[:], rendezvousID)

	cmd := CmdHost
	if !isHost {
		cmd = CmdJoin
	}

	greeting := &Greeting{
		Command:      cmd,
		RendezvousID: rID,
	}

	if _, err := conn.Write(greeting.Encode()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send greeting to relay: %w", err)
	}

	statusBuf := make([]byte, 1)

	if isHost {
		// Wait for StatusWaiting first
		if _, err := io.ReadFull(conn, statusBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to read initial status from relay: %w", err)
		}

		if statusBuf[0] == StatusBusy {
			conn.Close()
			return nil, ErrSessionBusy
		}
		if statusBuf[0] != StatusWaiting {
			conn.Close()
			return nil, fmt.Errorf("%w (code: 0x%x)", ErrRelayRejected, statusBuf[0])
		}

		// Now wait for StatusMatched (or timeout)
		if timeout > 0 {
			conn.SetReadDeadline(time.Now().Add(timeout))
		}
		if _, err := io.ReadFull(conn, statusBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("waiting for peer failed: %w", err)
		}
		conn.SetReadDeadline(time.Time{})

		if statusBuf[0] == StatusTimeout {
			conn.Close()
			return nil, ErrSessionTimeout
		}
		if statusBuf[0] != StatusMatched {
			conn.Close()
			return nil, fmt.Errorf("unexpected relay status: 0x%x", statusBuf[0])
		}
	} else {
		// Joiner expects immediate StatusMatched
		if timeout > 0 {
			conn.SetReadDeadline(time.Now().Add(timeout))
		}
		if _, err := io.ReadFull(conn, statusBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to connect to host: %w", err)
		}
		conn.SetReadDeadline(time.Time{})

		if statusBuf[0] == StatusError {
			conn.Close()
			return nil, fmt.Errorf("host not found or not yet registered on relay")
		}
		if statusBuf[0] != StatusMatched {
			conn.Close()
			return nil, fmt.Errorf("relay rejected join with status 0x%x", statusBuf[0])
		}
	}

	return conn, nil
}
