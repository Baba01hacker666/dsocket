package relay

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/websocket"
)

// Connect connects to the dsocket rendezvous relay server.
// It automatically detects whether relayAddr is a WebSocket URL (ws:// or wss://)
// or a standard TCP address (host:port).
func Connect(relayAddr string, rendezvousID []byte, isHost bool, timeout time.Duration) (net.Conn, error) {
	if len(rendezvousID) != RendezvousIDSize {
		return nil, fmt.Errorf("invalid rendezvous ID size: expected %d, got %d", RendezvousIDSize, len(rendezvousID))
	}

	if strings.HasPrefix(relayAddr, "ws://") || strings.HasPrefix(relayAddr, "wss://") {
		return connectWebSocket(relayAddr, rendezvousID, isHost, timeout)
	}

	return connectTCP(relayAddr, rendezvousID, isHost, timeout)
}

func connectWebSocket(wsURL string, rendezvousID []byte, isHost bool, timeout time.Duration) (net.Conn, error) {
	hexID := hex.EncodeToString(rendezvousID)
	role := "host"
	if !isHost {
		role = "join"
	}

	parsedURL, err := url.Parse(wsURL)
	if err != nil {
		return nil, fmt.Errorf("invalid websocket url: %w", err)
	}
	if parsedURL.Path == "" || parsedURL.Path == "/" {
		parsedURL.Path = "/relay"
	}
	q := parsedURL.Query()
	q.Set("id", hexID)
	q.Set("role", role)
	parsedURL.RawQuery = q.Encode()

	origin := "http://localhost/"
	if parsedURL.Scheme == "wss" {
		origin = "https://localhost/"
	}

	config, err := websocket.NewConfig(parsedURL.String(), origin)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		config.Dialer = &net.Dialer{Timeout: timeout}
	}

	ws, err := websocket.DialConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket relay %s: %w", parsedURL.Host, err)
	}
	ws.PayloadType = websocket.BinaryFrame

	// Wait for StatusMatched byte (0x20)
	statusBuf := make([]byte, 1)
	if timeout > 0 {
		ws.SetReadDeadline(time.Now().Add(timeout))
	}
	if _, err := io.ReadFull(ws, statusBuf); err != nil {
		ws.Close()
		return nil, fmt.Errorf("failed to read match status from websocket relay: %w", err)
	}
	ws.SetReadDeadline(time.Time{})

	if statusBuf[0] != StatusMatched {
		ws.Close()
		return nil, fmt.Errorf("websocket relay returned status 0x%x", statusBuf[0])
	}

	return ws, nil
}

func connectTCP(relayAddr string, rendezvousID []byte, isHost bool, timeout time.Duration) (net.Conn, error) {
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
