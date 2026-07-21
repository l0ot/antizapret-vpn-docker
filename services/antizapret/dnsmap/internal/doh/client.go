package doh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	MaxResponseSize = 65535
	MaxIdleConns    = 32
)

var ErrResponseTooLarge = errors.New("doh response is too large")

type ResponseError struct{ Message string }

func (e *ResponseError) Error() string { return e.Message }

type ProtocolError struct{ Message string }

func (e *ProtocolError) Error() string { return e.Message }

// Client is a small RFC 8484 GET client for AdGuard's local DoH endpoint.
// The standard Transport owns the keep-alive pool and is capped at 32 idle
// connections per upstream, matching the legacy connection pool.
type Client struct {
	host       string
	port       int
	httpClient *http.Client
	closeIdle  func()
}

func New(host string, port int, timeout time.Duration) *Client {
	transport := &http.Transport{
		Proxy:                 nil,
		MaxIdleConns:          MaxIdleConns,
		MaxIdleConnsPerHost:   MaxIdleConns,
		MaxConnsPerHost:       0,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	hc := &http.Client{Transport: transport, Timeout: timeout}
	return NewWithHTTPClient(host, port, hc, transport.CloseIdleConnections)
}

func NewWithHTTPClient(host string, port int, client *http.Client, closeIdle func()) *Client {
	return &Client{host: host, port: port, httpClient: client, closeIdle: closeIdle}
}

func (c *Client) Query(ctx context.Context, request *dns.Msg, clientID string) (*dns.Msg, error) {
	data, err := request.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack dns request: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	path := "/dns-query/" + url.PathEscape(clientID) + "?dns=" + encoded

	for attempt := 0; attempt < 2; attempt++ {
		response, transportErr := c.do(ctx, path)
		if transportErr == nil {
			return response, nil
		}
		var responseErr *ResponseError
		var protocolErr *ProtocolError
		if errors.As(transportErr, &responseErr) || errors.As(transportErr, &protocolErr) || errors.Is(transportErr, ErrResponseTooLarge) {
			return nil, transportErr
		}
		if attempt == 1 {
			return nil, transportErr
		}
		// Closing idle connections prevents the next attempt from reusing a
		// socket which the peer has already discarded.
		if c.closeIdle != nil {
			c.closeIdle()
		}
	}
	return nil, fmt.Errorf("unreachable doh retry state")
}

func (c *Client) do(ctx context.Context, path string) (*dns.Msg, error) {
	requestURL := "http://" + net.JoinHostPort(c.host, strconv.Itoa(c.port)) + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create doh request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh transport: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &ResponseError{Message: fmt.Sprintf("doh server returned http %d", resp.StatusCode)}
	}
	contentType := strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0])
	if contentType != "" && !strings.EqualFold(contentType, "application/dns-message") {
		return nil, &ResponseError{Message: fmt.Sprintf("unexpected doh content type %s", contentType)}
	}
	if rawLength := resp.Header.Get("Content-Length"); rawLength != "" {
		length, parseErr := strconv.ParseInt(strings.TrimSpace(rawLength), 10, 64)
		if parseErr != nil || length < 0 {
			return nil, &ResponseError{Message: "invalid doh content-length"}
		}
		if length > MaxResponseSize {
			return nil, ErrResponseTooLarge
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read doh response: %w", err)
	}
	if len(body) > MaxResponseSize {
		return nil, ErrResponseTooLarge
	}
	message := new(dns.Msg)
	if err := message.Unpack(body); err != nil {
		return nil, &ProtocolError{Message: fmt.Sprintf("invalid dns response: %v", err)}
	}
	return message, nil
}

func (c *Client) Close() {
	if c.closeIdle != nil {
		c.closeIdle()
	}
}
