package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dsocket/pkg/crypto"
	"dsocket/pkg/relay"
	"dsocket/pkg/secureconn"
)

const (
	DefaultRelayAddr = "127.0.0.1:8765"
	FileMagicMarker  = "DSKT_FILE_V1\n"
)

func getEnvRelay() string {
	if val := os.Getenv("DSOCKET_RELAY"); val != "" {
		return val
	}
	return DefaultRelayAddr
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	first := os.Args[1]

	// Ultra-short shortcuts:
	// dsocket -l [secret]
	if first == "-l" || first == "-listen" {
		secret := ""
		relayAddr := getEnvRelay()
		for i := 2; i < len(os.Args); i++ {
			if (os.Args[i] == "-r" || os.Args[i] == "-relay") && i+1 < len(os.Args) {
				relayAddr = os.Args[i+1]
				i++
			} else if !strings.HasPrefix(os.Args[i], "-") && secret == "" {
				secret = os.Args[i]
			}
		}
		runListenDirect(relayAddr, secret, false, "")
		return
	}

	// dsocket send <file> [secret]
	if first == "send" || first == "put" {
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: dsocket send <file> [secret]\n")
			os.Exit(1)
		}
		filePath := os.Args[2]
		secret := ""
		relayAddr := getEnvRelay()
		for i := 3; i < len(os.Args); i++ {
			if (os.Args[i] == "-r" || os.Args[i] == "-relay") && i+1 < len(os.Args) {
				relayAddr = os.Args[i+1]
				i++
			} else if !strings.HasPrefix(os.Args[i], "-") && secret == "" {
				secret = os.Args[i]
			}
		}
		runSendDirect(relayAddr, filePath, secret)
		return
	}

	// dsocket recv <secret> [-o output]
	if first == "recv" || first == "get" {
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: dsocket recv <secret> [-o output]\n")
			os.Exit(1)
		}
		secret := os.Args[2]
		outFile := ""
		relayAddr := getEnvRelay()
		for i := 3; i < len(os.Args); i++ {
			if (os.Args[i] == "-r" || os.Args[i] == "-relay") && i+1 < len(os.Args) {
				relayAddr = os.Args[i+1]
				i++
			} else if (os.Args[i] == "-o" || os.Args[i] == "-out") && i+1 < len(os.Args) {
				outFile = os.Args[i+1]
				i++
			}
		}
		runRecvDirect(relayAddr, secret, outFile)
		return
	}

	// Subcommands
	switch first {
	case "relay":
		runRelay(os.Args[2:])
	case "listen":
		runListen(os.Args[2:])
	case "connect":
		runConnect(os.Args[2:])
	case "forward", "fwd":
		runForward(os.Args[2:])
	case "gen":
		fmt.Println(generateSecret(12))
	case "version", "-v", "--version":
		fmt.Println("dsocket version 1.1.0 (Go E2EE Rendezvous Channel)")
	case "help", "-h", "--help":
		printUsage()
	default:
		// If first arg doesn't start with '-', treat it directly as secret to connect!
		// e.g.: dsocket <secret>
		if !strings.HasPrefix(first, "-") {
			secret := first
			relayAddr := getEnvRelay()
			for i := 2; i < len(os.Args); i++ {
				if (os.Args[i] == "-r" || os.Args[i] == "-relay") && i+1 < len(os.Args) {
					relayAddr = os.Args[i+1]
					i++
				}
			}
			runConnectDirect(relayAddr, secret, "")
			return
		}

		fmt.Fprintf(os.Stderr, "Unknown command or argument: %s\n\n", first)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`dsocket - End-to-End Encrypted Rendezvous Channel

FAST USAGE:
  # File Transfer:
  dsocket send <file>              Send file (prints secret)
  dsocket recv <secret>            Receive file

  # Encrypted Netcat Pipe:
  dsocket -l                       Listen (prints secret)
  dsocket <secret>                 Connect to waiting peer

  # Relay Server:
  dsocket relay [:port]            Run rendezvous server (default :8765)

DETAILED COMMANDS:
  dsocket send <file> [secret] [-r relay:port]
  dsocket recv <secret> [-o out] [-r relay:port]
  dsocket -l [secret] [-r relay:port]
  dsocket <secret> [-r relay:port]
  dsocket forward -role host -target 127.0.0.1:3000 -s <secret>
  dsocket forward -role join -listen 127.0.0.1:8080 -s <secret>

ENVIRONMENT:
  DSOCKET_RELAY                    Default relay address (currently: %s)
`, getEnvRelay())
}

// ---------------------------------------------------------------------
// FAST DIRECT HANDLERS
// ---------------------------------------------------------------------

func runSendDirect(relayAddr, filePath, secret string) {
	if _, err := os.Stat(filePath); err != nil {
		fmt.Fprintf(os.Stderr, "[-] File not found: %s\n", filePath)
		os.Exit(1)
	}

	if secret == "" {
		secret = generateSecret(12)
	}

	fmt.Fprintf(os.Stderr, "[*] Secret code: %s\n", secret)
	fmt.Fprintf(os.Stderr, "[*] To receive on peer run:  dsocket recv %s\n", secret)
	fmt.Fprintf(os.Stderr, "[*] Waiting for peer to connect...\n")

	rID := crypto.DeriveRendezvousID(secret)
	rawConn, err := relay.Connect(relayAddr, rID, true, 10*time.Minute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Relay error: %v\n", err)
		os.Exit(1)
	}
	defer rawConn.Close()

	sConn, err := secureconn.Handshake(rawConn, secret, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Handshake error: %v\n", err)
		os.Exit(1)
	}
	defer sConn.Close()

	sendFile(sConn, filePath)
}

func runRecvDirect(relayAddr, secret, outFile string) {
	fmt.Fprintf(os.Stderr, "[*] Connecting to peer for code: %s...\n", secret)
	rID := crypto.DeriveRendezvousID(secret)

	rawConn, err := relay.Connect(relayAddr, rID, false, 30*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection error: %v\n", err)
		os.Exit(1)
	}
	defer rawConn.Close()

	sConn, err := secureconn.Handshake(rawConn, secret, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Handshake error: %v\n", err)
		os.Exit(1)
	}
	defer sConn.Close()

	receiveFile(sConn, outFile)
}

func runListenDirect(relayAddr, secret string, fileRecv bool, fileOut string) {
	if secret == "" {
		secret = generateSecret(12)
		fmt.Fprintf(os.Stderr, "[*] Secret code: %s\n", secret)
		fmt.Fprintf(os.Stderr, "[*] To connect on peer run:  dsocket %s\n", secret)
	}
	fmt.Fprintf(os.Stderr, "[*] Listening on relay %s...\n", relayAddr)

	rID := crypto.DeriveRendezvousID(secret)
	rawConn, err := relay.Connect(relayAddr, rID, true, 10*time.Minute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Relay error: %v\n", err)
		os.Exit(1)
	}
	defer rawConn.Close()

	sConn, err := secureconn.Handshake(rawConn, secret, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Handshake error: %v\n", err)
		os.Exit(1)
	}
	defer sConn.Close()

	fmt.Fprintf(os.Stderr, "[+] Connected securely.\n")

	if fileRecv {
		receiveFile(sConn, fileOut)
	} else {
		bidirectionalPipe(sConn)
	}
}

func runConnectDirect(relayAddr, secret, fileSend string) {
	fmt.Fprintf(os.Stderr, "[*] Connecting via relay %s...\n", relayAddr)
	rID := crypto.DeriveRendezvousID(secret)

	rawConn, err := relay.Connect(relayAddr, rID, false, 30*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Connection error: %v\n", err)
		os.Exit(1)
	}
	defer rawConn.Close()

	sConn, err := secureconn.Handshake(rawConn, secret, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Handshake error: %v\n", err)
		os.Exit(1)
	}
	defer sConn.Close()

	fmt.Fprintf(os.Stderr, "[+] Connected securely.\n")

	if fileSend != "" {
		sendFile(sConn, fileSend)
	} else {
		bidirectionalPipe(sConn)
	}
}

// ---------------------------------------------------------------------
// RELAY SERVER COMMAND
// ---------------------------------------------------------------------

func runRelay(args []string) {
	listenAddr := ":8765"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		listenAddr = args[0]
	} else {
		fs := flag.NewFlagSet("relay", flag.ExitOnError)
		listenPtr := fs.String("listen", ":8765", "Address and port to listen on")
		fs.Parse(args)
		listenAddr = *listenPtr
	}

	server := relay.NewServer(listenAddr, 5*time.Minute)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start relay server: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("[dsocket-relay] shutting down server...")
	server.Close()
}

// ---------------------------------------------------------------------
// EXTENDED LISTEN & CONNECT FLAGS
// ---------------------------------------------------------------------

func runListen(args []string) {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	relayAddr := fs.String("relay", getEnvRelay(), "Relay server address")
	fs.StringVar(relayAddr, "r", getEnvRelay(), "Relay server address (short)")
	secret := fs.String("s", "", "Shared secret")
	fileRecv := fs.Bool("file-recv", false, "Receive file mode")
	fileOut := fs.String("o", "", "Destination file path")
	fs.Parse(args)

	runListenDirect(*relayAddr, *secret, *fileRecv, *fileOut)
}

func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	relayAddr := fs.String("relay", getEnvRelay(), "Relay server address")
	fs.StringVar(relayAddr, "r", getEnvRelay(), "Relay server address (short)")
	secret := fs.String("s", "", "Shared secret")
	fileSend := fs.String("file-send", "", "File to send")
	fs.Parse(args)

	if *secret == "" && len(fs.Args()) > 0 {
		*secret = fs.Args()[0]
	}
	if *secret == "" {
		fmt.Fprintf(os.Stderr, "Error: secret is required.\n")
		os.Exit(1)
	}

	runConnectDirect(*relayAddr, *secret, *fileSend)
}

// ---------------------------------------------------------------------
// PORT FORWARDING COMMAND
// ---------------------------------------------------------------------

func runForward(args []string) {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	role := fs.String("role", "host", "Role: 'host' or 'join'")
	relayAddr := fs.String("relay", getEnvRelay(), "Relay address")
	fs.StringVar(relayAddr, "r", getEnvRelay(), "Relay address (short)")
	secret := fs.String("s", "", "Shared secret")
	listenAddr := fs.String("listen", "", "Local listen address (for join)")
	fs.StringVar(listenAddr, "l", "", "Local listen address (short)")
	targetAddr := fs.String("target", "", "Target address (for host)")
	fs.StringVar(targetAddr, "t", "", "Target address (short)")
	fs.Parse(args)

	if *secret == "" {
		fmt.Fprintf(os.Stderr, "Error: -s <secret> is required.\n")
		os.Exit(1)
	}

	isHost := strings.ToLower(*role) == "host"
	if isHost && *targetAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: -t <host:port> required for host role.\n")
		os.Exit(1)
	}
	if !isHost && *listenAddr == "" {
		fmt.Fprintf(os.Stderr, "Error: -l <host:port> required for join role.\n")
		os.Exit(1)
	}

	rID := crypto.DeriveRendezvousID(*secret)

	if isHost {
		fmt.Fprintf(os.Stderr, "[*] Waiting on relay %s to forward -> %s\n", *relayAddr, *targetAddr)
		rawConn, err := relay.Connect(*relayAddr, rID, true, 10*time.Minute)
		if err != nil {
			log.Fatalf("Relay error: %v", err)
		}
		defer rawConn.Close()

		sConn, err := secureconn.Handshake(rawConn, *secret, true)
		if err != nil {
			log.Fatalf("Handshake error: %v", err)
		}
		defer sConn.Close()

		targetConn, err := net.Dial("tcp", *targetAddr)
		if err != nil {
			log.Fatalf("Failed to connect to target %s: %v", *targetAddr, err)
		}
		defer targetConn.Close()

		fmt.Fprintf(os.Stderr, "[+] Tunnel bridged to %s\n", *targetAddr)
		bridgeStreams(sConn, targetConn)
	} else {
		ln, err := net.Listen("tcp", *listenAddr)
		if err != nil {
			log.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
		}
		defer ln.Close()
		fmt.Fprintf(os.Stderr, "[+] Listening on %s. Waiting for local client...\n", *listenAddr)

		clientConn, err := ln.Accept()
		if err != nil {
			log.Fatalf("Accept failed: %v", err)
		}
		defer clientConn.Close()

		rawConn, err := relay.Connect(*relayAddr, rID, false, 30*time.Second)
		if err != nil {
			log.Fatalf("Relay error: %v", err)
		}
		defer rawConn.Close()

		sConn, err := secureconn.Handshake(rawConn, *secret, false)
		if err != nil {
			log.Fatalf("Handshake error: %v", err)
		}
		defer sConn.Close()

		fmt.Fprintf(os.Stderr, "[+] Tunnel bridged!\n")
		bridgeStreams(clientConn, sConn)
	}
}

// ---------------------------------------------------------------------
// PIPING & FILE TRANSFER
// ---------------------------------------------------------------------

func bidirectionalPipe(conn net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(conn, os.Stdin)
		conn.Close()
		done <- struct{}{}
	}()

	go func() {
		io.Copy(os.Stdout, conn)
		done <- struct{}{}
	}()

	<-done
}

func sendFile(conn net.Conn, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to open file: %v\n", err)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Stat error: %v\n", err)
		return
	}

	fmt.Fprintf(os.Stderr, "[*] Calculating checksum...\n")
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Checksum failed: %v\n", err)
		return
	}
	f.Seek(0, io.SeekStart)
	checksum := hex.EncodeToString(hasher.Sum(nil))

	baseName := filepath.Base(filePath)
	header := fmt.Sprintf("%s%s\n%d\n%s\n", FileMagicMarker, baseName, fi.Size(), checksum)

	fmt.Fprintf(os.Stderr, "[*] Sending: %s (%d bytes)\n", baseName, fi.Size())
	if _, err := conn.Write([]byte(header)); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to send header: %v\n", err)
		return
	}

	start := time.Now()
	n, err := io.Copy(conn, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] File transfer interrupted: %v\n", err)
		return
	}
	elapsed := time.Since(start)
	rateMB := float64(n) / (1024 * 1024) / elapsed.Seconds()

	fmt.Fprintf(os.Stderr, "[+] Sent %d bytes in %v (%.2f MB/s)\n", n, elapsed.Round(time.Millisecond), rateMB)
}

func receiveFile(conn net.Conn, outPath string) {
	reader := bufio.NewReader(conn)

	magic, err := reader.ReadString('\n')
	if err != nil || magic != FileMagicMarker {
		fmt.Fprintf(os.Stderr, "[-] Protocol error: invalid header\n")
		return
	}

	origName, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read filename\n")
		return
	}
	origName = strings.TrimSpace(origName)

	sizeStr, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read size\n")
		return
	}
	size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Invalid size\n")
		return
	}

	expectedChecksum, err := reader.ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to read checksum\n")
		return
	}
	expectedChecksum = strings.TrimSpace(expectedChecksum)

	targetPath := outPath
	if targetPath == "" {
		targetPath = origName
	}

	outFile, err := os.Create(targetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to create output file: %v\n", err)
		return
	}
	defer outFile.Close()

	fmt.Fprintf(os.Stderr, "[*] Receiving %s (%d bytes)...\n", targetPath, size)

	hasher := sha256.New()
	mw := io.MultiWriter(outFile, hasher)

	start := time.Now()
	copied, err := io.CopyN(mw, reader, size)
	if err != nil && err != io.EOF {
		fmt.Fprintf(os.Stderr, "[-] Transfer failed: %v\n", err)
		return
	}

	actualChecksum := hex.EncodeToString(hasher.Sum(nil))
	if actualChecksum != expectedChecksum {
		fmt.Fprintf(os.Stderr, "[-] CHECKSUM MISMATCH!\nExpected: %s\nActual:   %s\n", expectedChecksum, actualChecksum)
		return
	}

	elapsed := time.Since(start)
	rateMB := float64(copied) / (1024 * 1024) / elapsed.Seconds()
	fmt.Fprintf(os.Stderr, "[+] Saved %s (verified SHA-256) in %v (%.2f MB/s)\n", targetPath, elapsed.Round(time.Millisecond), rateMB)
}

func bridgeStreams(a, b io.ReadWriteCloser) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(a, b)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(b, a)
		done <- struct{}{}
	}()

	<-done
}

// ---------------------------------------------------------------------
// HELPERS
// ---------------------------------------------------------------------

// generateSecret generates readable hyphenated codes e.g. "7y4m-k8px-w2zq"
func generateSecret(n int) string {
	const charset = "abcdefghjkmnpqrstuvwxyz23456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		b[i] = charset[num.Int64()]
	}
	str := string(b)
	if len(str) == 12 {
		return str[0:4] + "-" + str[4:8] + "-" + str[8:12]
	}
	return str
}
