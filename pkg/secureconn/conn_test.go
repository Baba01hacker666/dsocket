package secureconn

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	ch := make(chan net.Conn)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("accept failed: %v", err)
			return
		}
		ch <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	server := <-ch
	return client, server
}

func TestSecureConnSuccess(t *testing.T) {
	clientConn, serverConn := tcpPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	secret := "passphrase-for-test-secureconn-1234"

	var hostConn, joinConn *Conn
	var hostErr, joinErr error

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		hostConn, hostErr = Handshake(serverConn, secret, true)
	}()

	go func() {
		defer wg.Done()
		joinConn, joinErr = Handshake(clientConn, secret, false)
	}()

	wg.Wait()

	if hostErr != nil {
		t.Fatalf("host handshake failed: %v", hostErr)
	}
	if joinErr != nil {
		t.Fatalf("joiner handshake failed: %v", joinErr)
	}
	defer hostConn.Close()
	defer joinConn.Close()

	// Test 1: Small message
	msg1 := []byte("ping from host")
	go func() {
		_, err := hostConn.Write(msg1)
		if err != nil {
			t.Errorf("host write error: %v", err)
		}
	}()

	buf1 := make([]byte, len(msg1))
	_, err := io.ReadFull(joinConn, buf1)
	if err != nil {
		t.Fatalf("join read error: %v", err)
	}
	if !bytes.Equal(msg1, buf1) {
		t.Fatalf("received %q, expected %q", buf1, msg1)
	}

	// Test 2: Large multi-chunk payload (e.g. 100 KB)
	largeData := make([]byte, 100*1024)
	rand.Read(largeData)

	go func() {
		_, err := joinConn.Write(largeData)
		if err != nil {
			t.Errorf("join large write error: %v", err)
		}
	}()

	recvBuf := make([]byte, len(largeData))
	_, err = io.ReadFull(hostConn, recvBuf)
	if err != nil {
		t.Fatalf("host large read error: %v", err)
	}
	if !bytes.Equal(largeData, recvBuf) {
		t.Fatalf("large data mismatch")
	}
}

func TestSecureConnWrongSecret(t *testing.T) {
	clientConn, serverConn := tcpPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	var hostErr, joinErr error
	go func() {
		defer wg.Done()
		_, hostErr = Handshake(serverConn, "secret-one", true)
	}()

	go func() {
		defer wg.Done()
		_, joinErr = Handshake(clientConn, "secret-two", false)
	}()

	wg.Wait()

	if hostErr == nil && joinErr == nil {
		t.Fatalf("expected handshake failure for mismatched secrets, got nil error")
	}
}
