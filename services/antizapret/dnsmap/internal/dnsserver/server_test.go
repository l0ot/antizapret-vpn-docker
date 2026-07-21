package dnsserver

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type testResolver struct{}

func (testResolver) Resolve(_ context.Context, request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("14.16.0.2").To4()}}
	return response
}

func dnsRequest(t testing.TB) []byte {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	data, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestUDPAndTCPListenersAndMalformedPackets(t *testing.T) {
	server := New("127.0.0.1", 0, true, time.Second, false, "127.0.0.1:1", testResolver{}, nil)
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()

	requestData := dnsRequest(t)
	udpConn, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	if _, err := udpConn.Write(requestData); err != nil {
		t.Fatal(err)
	}
	if err := udpConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	udpResponse := make([]byte, 65535)
	n, _, err := udpConn.ReadFromUDP(udpResponse)
	if err != nil {
		t.Fatal(err)
	}
	checkResponse(t, udpResponse[:n])
	if _, err := udpConn.Write([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := udpConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := udpConn.ReadFromUDP(udpResponse); err == nil {
		t.Fatal("malformed packet unexpectedly received a response")
	}

	tcpConn, err := net.DialTimeout("tcp", server.TCPAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConn.Close()
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(requestData)))
	if _, err := tcpConn.Write(append(length[:], requestData...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(tcpConn, length[:]); err != nil {
		t.Fatal(err)
	}
	responseData := make([]byte, binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(tcpConn, responseData); err != nil {
		t.Fatal(err)
	}
	checkResponse(t, responseData)
}

func checkResponse(t testing.TB, data []byte) {
	t.Helper()
	response := new(dns.Msg)
	if err := response.Unpack(data); err != nil {
		t.Fatal(err)
	}
	if len(response.Answer) != 1 || response.Rcode != dns.RcodeSuccess {
		t.Fatalf("unexpected DNS response: %s", response)
	}
}

func TestConcurrentUDPRequests(t *testing.T) {
	server := New("127.0.0.1", 0, false, time.Second, false, "127.0.0.1:1", testResolver{}, nil)
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	requestData := dnsRequest(t)
	var failures int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
			if err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write(requestData)
			buffer := make([]byte, 65535)
			if _, _, err := conn.ReadFromUDP(buffer); err != nil {
				mu.Lock()
				failures++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if failures != 0 {
		t.Fatalf("concurrent UDP failures: %d", failures)
	}
}

func TestPassthroughPreservesUDPWireData(t *testing.T) {
	upstream, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		buffer := make([]byte, 65535)
		n, remote, readErr := upstream.ReadFromUDP(buffer)
		if readErr == nil {
			_, _ = upstream.WriteToUDP(buffer[:n], remote)
		}
	}()
	server := New("127.0.0.1", 0, false, time.Second, true, upstream.LocalAddr().String(), nil, nil)
	if err := server.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer server.Shutdown()
	conn, err := net.DialUDP("udp", nil, server.UDPAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	requestData := []byte{0, 7, 1, 2, 3, 4}
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write(requestData); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(response)
	if err != nil {
		t.Fatal(err)
	}
	if string(response[:n]) != string(requestData) {
		t.Fatalf("passthrough changed packet: %v", response[:n])
	}
}
