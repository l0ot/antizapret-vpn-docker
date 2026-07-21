package doh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func validDNSBody(t testing.TB) []byte {
	t.Helper()
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1").To4()}}
	data, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func httpResponse(body []byte, contentType string, status int) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	header.Set("Content-Length", strconv.Itoa(len(body)))
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(bytes.NewReader(body))}
}

func TestQueryURLAndContentValidation(t *testing.T) {
	body := validDNSBody(t)
	var gotPath string
	var gotQuery string
	var gotAccept string
	client := NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		gotPath, gotQuery, gotAccept = request.URL.EscapedPath(), request.URL.RawQuery, request.Header.Get("Accept")
		return httpResponse(body, "application/dns-message; charset=binary", http.StatusOK), nil
	})}, nil)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	if _, err := client.Query(context.Background(), request, "client/id"); err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(gotQuery)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/dns-query/client%2Fid" || gotAccept != "application/dns-message" || strings.Contains(values.Get("dns"), "=") {
		t.Fatalf("unexpected request path/query: %q %q %q", gotPath, gotQuery, gotAccept)
	}
}

func TestRetryOnlyTransportError(t *testing.T) {
	var calls atomic.Int32
	client := NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return nil, errors.New("stale connection")
		}
		return httpResponse(validDNSBody(t), "application/dns-message", http.StatusOK), nil
	})}, nil)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	if _, err := client.Query(context.Background(), request, "client"); err != nil || calls.Load() != 2 {
		t.Fatalf("transport retry failed: calls=%d err=%v", calls.Load(), err)
	}
	for _, test := range []struct {
		name     string
		response *http.Response
	}{
		{name: "status", response: httpResponse(nil, "application/dns-message", http.StatusServiceUnavailable)},
		{name: "content type", response: httpResponse([]byte("bad"), "text/plain", http.StatusOK)},
		{name: "content length", response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Length": []string{"invalid"}}, Body: io.NopCloser(strings.NewReader("bad"))}},
		{name: "malformed DNS", response: httpResponse([]byte("not dns"), "application/dns-message", http.StatusOK)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var count atomic.Int32
			c := NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
				count.Add(1)
				return test.response, nil
			})}, nil)
			_, err := c.Query(context.Background(), request, "client")
			if err == nil || count.Load() != 1 {
				t.Fatalf("err=%v calls=%d", err, count.Load())
			}
		})
	}
}

func TestOversizedResponseAndMissingContentType(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	if _, err := NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return httpResponse(validDNSBody(t), "", http.StatusOK), nil
	})}, nil).Query(context.Background(), request, "client"); err != nil {
		t.Fatal("missing Content-Type should be accepted:", err)
	}
	_, err := NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return httpResponse(make([]byte, MaxResponseSize+1), "application/dns-message", http.StatusOK), nil
	})}, nil).Query(context.Background(), request, "client")
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestKeepAliveIsReusedAndCloseClosesIdleConnections(t *testing.T) {
	body := validDNSBody(t)
	var connections atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(body)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := New(parsed.Hostname(), mustPort(t, parsed), time.Second)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	for i := 0; i < 2; i++ {
		if _, err := client.Query(context.Background(), request, "client"); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("expected one keep-alive connection, got %d", connections.Load())
	}
	var closed atomic.Bool
	client = NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return httpResponse(body, "application/dns-message", http.StatusOK), nil
	})}, func() { closed.Store(true) })
	if _, err := client.Query(context.Background(), request, "client"); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if !closed.Load() {
		t.Fatal("Close did not close idle connections")
	}
}

func mustPort(t testing.TB, parsed *url.URL) int {
	t.Helper()
	port, err := strconv.Atoi(parsed.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func FuzzDoHResponseValidation(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Fuzz(func(t *testing.T, body []byte) {
		request := new(dns.Msg)
		request.SetQuestion("example.com.", dns.TypeA)
		client := NewWithHTTPClient("adguard", 3000, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return httpResponse(body, "application/dns-message", http.StatusOK), nil
		})}, nil)
		_, _ = client.Query(context.Background(), request, "client")
	})
}

func BenchmarkConcurrentDoHRequests(b *testing.B) {
	body := validDNSBody(b)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		b.Fatal(err)
	}
	client := New(parsed.Hostname(), mustPort(b, parsed), time.Second)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := client.Query(context.Background(), request, "client"); err != nil {
				b.Error(err)
			}
		}
	})
}
