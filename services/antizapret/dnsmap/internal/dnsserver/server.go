package dnsserver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const maxDNSMessageSize = 65535

type Resolver interface {
	Resolve(ctx context.Context, request *dns.Msg) *dns.Msg
}

type Server struct {
	address     string
	port        int
	tcp         bool
	timeout     time.Duration
	passthrough bool
	upstream    string
	resolver    Resolver
	logger      *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	udp    *net.UDPConn
	tcpLn  net.Listener
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
	once   sync.Once
}

func New(address string, port int, tcp bool, timeout time.Duration, passthrough bool, upstream string, resolver Resolver, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{address: address, port: port, tcp: tcp, timeout: timeout,
		passthrough: passthrough, upstream: upstream, resolver: resolver,
		logger: logger, conns: make(map[net.Conn]struct{})}
}

func (s *Server) Start(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	s.ctx, s.cancel = ctx, cancel
	udpAddress, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.address, strconv.Itoa(s.port)))
	if err != nil {
		cancel()
		return fmt.Errorf("resolve DNS listen address: %w", err)
	}
	udp, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		cancel()
		return fmt.Errorf("listen for UDP DNS: %w", err)
	}
	s.udp = udp
	if s.tcp {
		listenPort := s.port
		if listenPort == 0 {
			listenPort = s.udp.LocalAddr().(*net.UDPAddr).Port
		}
		tcpListener, listenErr := net.Listen("tcp", net.JoinHostPort(s.address, strconv.Itoa(listenPort)))
		if listenErr != nil {
			_ = udp.Close()
			cancel()
			return fmt.Errorf("listen for TCP DNS: %w", listenErr)
		}
		s.tcpLn = tcpListener
	}
	s.wg.Add(1)
	go s.serveUDP()
	if s.tcp {
		s.wg.Add(1)
		go s.acceptTCP()
	}
	s.logger.Info("DNS listener started", "address", s.address, "port", s.port, "transport", s.transportDescription())
	return nil
}

func (s *Server) UDPAddr() net.Addr {
	if s.udp == nil {
		return nil
	}
	return s.udp.LocalAddr()
}

func (s *Server) TCPAddr() net.Addr {
	if s.tcpLn == nil {
		return nil
	}
	return s.tcpLn.Addr()
}

func (s *Server) transportDescription() string {
	if s.tcp {
		return "udp/tcp"
	}
	return "udp"
}

func (s *Server) Shutdown() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		if s.cancel != nil {
			s.cancel()
		}
		if s.udp != nil {
			_ = s.udp.Close()
		}
		if s.tcpLn != nil {
			_ = s.tcpLn.Close()
		}
		s.mu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
	})
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buffer := make([]byte, maxDNSMessageSize)
	for {
		n, remote, err := s.udp.ReadFromUDP(buffer)
		if err != nil {
			if s.isClosed() {
				return
			}
			s.logger.Error("UDP DNS read failed", "error", err)
			continue
		}
		data := append([]byte(nil), buffer[:n]...)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleUDP(remote, data)
		}()
	}
}

func (s *Server) handleUDP(remote *net.UDPAddr, requestData []byte) {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()
	var responseData []byte
	var err error
	if s.passthrough {
		responseData, err = s.forwardUDP(ctx, requestData)
	} else {
		responseData, err = s.resolvePacket(ctx, requestData)
	}
	if err != nil {
		s.logger.Error("DNS request processing failed", "error", err)
		return
	}
	if _, err := s.udp.WriteToUDP(responseData, remote); err != nil && !s.isClosed() {
		s.logger.Error("UDP DNS write failed", "error", err)
	}
}

func (s *Server) acceptTCP() {
	defer s.wg.Done()
	for {
		conn, err := s.tcpLn.Accept()
		if err != nil {
			if s.isClosed() {
				return
			}
			s.logger.Error("TCP DNS accept failed", "error", err)
			continue
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				_ = conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.serveTCPConn(conn)
		}()
	}
}

func (s *Server) serveTCPConn(conn net.Conn) {
	for {
		if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
			return
		}
		var lengthBytes [2]byte
		if _, err := io.ReadFull(conn, lengthBytes[:]); err != nil {
			return
		}
		length := int(binary.BigEndian.Uint16(lengthBytes[:]))
		if length == 0 {
			return
		}
		requestData := make([]byte, length)
		if _, err := io.ReadFull(conn, requestData); err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
		var responseData []byte
		var err error
		if s.passthrough {
			responseData, err = s.forwardTCP(ctx, requestData)
		} else {
			responseData, err = s.resolvePacket(ctx, requestData)
		}
		cancel()
		if err != nil {
			s.logger.Error("DNS request processing failed", "error", err)
			return
		}
		if len(responseData) > maxDNSMessageSize {
			return
		}
		binary.BigEndian.PutUint16(lengthBytes[:], uint16(len(responseData)))
		if _, err := conn.Write(append(lengthBytes[:0:0], append(lengthBytes[:], responseData...)...)); err != nil {
			return
		}
	}
}

func (s *Server) resolvePacket(ctx context.Context, requestData []byte) ([]byte, error) {
	request := new(dns.Msg)
	if err := request.Unpack(requestData); err != nil {
		return nil, fmt.Errorf("parse DNS request: %w", err)
	}
	response := s.resolver.Resolve(ctx, request)
	if response == nil {
		return nil, fmt.Errorf("resolver returned nil response")
	}
	data, err := response.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS response: %w", err)
	}
	return data, nil
}

func (s *Server) forwardUDP(ctx context.Context, requestData []byte) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "udp", s.upstream)
	if err != nil {
		return nil, fmt.Errorf("dial UDP upstream: %w", err)
	}
	defer conn.Close()
	if _, err := conn.Write(requestData); err != nil {
		return nil, fmt.Errorf("write UDP upstream: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, fmt.Errorf("set UDP upstream deadline: %w", err)
	}
	buffer := make([]byte, maxDNSMessageSize)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, fmt.Errorf("read UDP upstream: %w", err)
	}
	return append([]byte(nil), buffer[:n]...), nil
}

func (s *Server) forwardTCP(ctx context.Context, requestData []byte) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", s.upstream)
	if err != nil {
		return nil, fmt.Errorf("dial TCP upstream: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, fmt.Errorf("set TCP upstream deadline: %w", err)
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(requestData)))
	if _, err := conn.Write(append(length[:0:0], append(length[:], requestData...)...)); err != nil {
		return nil, fmt.Errorf("write TCP upstream: %w", err)
	}
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, fmt.Errorf("read TCP upstream length: %w", err)
	}
	responseLength := int(binary.BigEndian.Uint16(length[:]))
	if responseLength == 0 {
		return nil, fmt.Errorf("TCP upstream returned an empty DNS message")
	}
	response := make([]byte, responseLength)
	if _, err := io.ReadFull(conn, response); err != nil {
		return nil, fmt.Errorf("read TCP upstream response: %w", err)
	}
	return response, nil
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}
