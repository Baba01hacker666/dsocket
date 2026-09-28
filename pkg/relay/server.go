package relay

import (
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type pendingHost struct {
	conn      net.Conn
	createdAt time.Time
	matched   chan net.Conn
}

// Server is a standalone, blind rendezvous relay server.
// It matches endpoints using 32-byte rendezvous hashes and bridges raw streams.
// It cannot see, decrypt, or inspect the underlying end-to-end encrypted traffic.
type Server struct {
	addr        string
	listener    net.Listener
	mu          sync.Mutex
	hosts       map[[RendezvousIDSize]byte]*pendingHost
	hostTimeout time.Duration

	closed bool
	quit   chan struct{}
}

func NewServer(addr string, hostTimeout time.Duration) *Server {
	if hostTimeout <= 0 {
		hostTimeout = 3 * time.Minute
	}
	return &Server{
		addr:        addr,
		hosts:       make(map[[RendezvousIDSize]byte]*pendingHost),
		hostTimeout: hostTimeout,
		quit:        make(chan struct{}),
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = ln
	log.Printf("[dsocket-relay] listening on %s (session timeout: %v)", ln.Addr().String(), s.hostTimeout)

	go s.cleanupLoop()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-s.quit:
					return
				default:
					log.Printf("[dsocket-relay] accept error: %v", err)
					return
				}
			}
			go s.handleConn(conn)
		}
	}()

	return nil
}

func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.quit)
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	// Read greeting
	greetingBuf := make([]byte, GreetingSize)
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(conn, greetingBuf); err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})

	greeting, err := DecodeGreeting(greetingBuf)
	if err != nil {
		conn.Write([]byte{StatusError})
		conn.Close()
		return
	}

	sessionKey := greeting.RendezvousID

	if greeting.Command == CmdHost {
		s.handleHost(conn, sessionKey)
	} else if greeting.Command == CmdJoin {
		s.handleJoin(conn, sessionKey)
	}
}

func (s *Server) handleHost(conn net.Conn, sessionKey [RendezvousIDSize]byte) {
	s.mu.Lock()
	if _, exists := s.hosts[sessionKey]; exists {
		s.mu.Unlock()
		conn.Write([]byte{StatusBusy})
		conn.Close()
		return
	}

	matchedChan := make(chan net.Conn, 1)
	s.hosts[sessionKey] = &pendingHost{
		conn:      conn,
		createdAt: time.Now(),
		matched:   matchedChan,
	}
	s.mu.Unlock()

	// Notify host that it is waiting
	if _, err := conn.Write([]byte{StatusWaiting}); err != nil {
		s.mu.Lock()
		delete(s.hosts, sessionKey)
		s.mu.Unlock()
		conn.Close()
		return
	}

	log.Printf("[dsocket-relay] session %s registered, waiting for joiner...", FormatID(sessionKey))

	// Wait for match or timeout
	select {
	case joinerConn, ok := <-matchedChan:
		if !ok || joinerConn == nil {
			return
		}
		log.Printf("[dsocket-relay] session %s matched! Bridging streams...", FormatID(sessionKey))
		// Inform host that peer matched
		if _, err := conn.Write([]byte{StatusMatched}); err != nil {
			conn.Close()
			joinerConn.Close()
			return
		}
		// Bridge host and joiner
		s.bridgeStreams(conn, joinerConn)

	case <-time.After(s.hostTimeout):
		s.mu.Lock()
		if cur, ok := s.hosts[sessionKey]; ok && cur.conn == conn {
			delete(s.hosts, sessionKey)
		}
		s.mu.Unlock()
		conn.Write([]byte{StatusTimeout})
		conn.Close()
		log.Printf("[dsocket-relay] session %s expired without joiner", FormatID(sessionKey))

	case <-s.quit:
		conn.Close()
	}
}

func (s *Server) handleJoin(conn net.Conn, sessionKey [RendezvousIDSize]byte) {
	s.mu.Lock()
	host, exists := s.hosts[sessionKey]
	if !exists {
		s.mu.Unlock()
		// Host not found or not yet connected
		conn.Write([]byte{StatusError})
		conn.Close()
		return
	}

	delete(s.hosts, sessionKey)
	s.mu.Unlock()

	// Send matched to joiner
	if _, err := conn.Write([]byte{StatusMatched}); err != nil {
		conn.Close()
		host.matched <- nil
		return
	}

	host.matched <- conn
}

func (s *Server) bridgeStreams(a, b net.Conn) {
	defer a.Close()
	defer b.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		if tc, ok := a.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(b, a)
		if tc, ok := b.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.quit:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.hosts {
				if now.Sub(v.createdAt) > s.hostTimeout {
					delete(s.hosts, k)
					v.conn.Write([]byte{StatusTimeout})
					v.conn.Close()
					close(v.matched)
				}
			}
			s.mu.Unlock()
		}
	}
}
