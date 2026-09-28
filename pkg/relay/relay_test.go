package relay

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"

	"dsocket/pkg/crypto"
)

func TestRelayMatching(t *testing.T) {
	srv := NewServer("127.0.0.1:0", 5*time.Second)
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start relay server: %v", err)
	}
	defer srv.Close()

	relayAddr := srv.Addr().String()
	secret := "rendezvous-test-secret"
	rendezvousID := crypto.DeriveRendezvousID(secret)

	var hostConn, joinConn io.ReadWriteCloser
	var hostErr, joinErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		conn, err := Connect(relayAddr, rendezvousID, true, 5*time.Second)
		hostConn = conn
		hostErr = err
	}()

	// Wait slightly so host registers first
	time.Sleep(50 * time.Millisecond)

	go func() {
		defer wg.Done()
		conn, err := Connect(relayAddr, rendezvousID, false, 5*time.Second)
		joinConn = conn
		joinErr = err
	}()

	wg.Wait()

	if hostErr != nil {
		t.Fatalf("host connect failed: %v", hostErr)
	}
	if joinErr != nil {
		t.Fatalf("join connect failed: %v", joinErr)
	}
	defer hostConn.Close()
	defer joinConn.Close()

	// Send message through bridged relay
	msg := []byte("hello through relay")
	go func() {
		hostConn.Write(msg)
	}()

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(joinConn, buf); err != nil {
		t.Fatalf("failed to read from joiner: %v", err)
	}

	if !bytes.Equal(msg, buf) {
		t.Fatalf("got %q, expected %q", buf, msg)
	}
}
