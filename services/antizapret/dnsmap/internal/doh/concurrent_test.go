package doh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestOneHundredConcurrentQueries(t *testing.T) {
	body := validDNSBody(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := New(parsed.Hostname(), mustPort(t, parsed), time.Second)
	request := new(dns.Msg)
	request.SetQuestion("example.com.", dns.TypeA)
	var wg sync.WaitGroup
	errorsFound := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := client.Query(context.Background(), request, "az-local")
			if err != nil {
				errorsFound <- err
			}
		}()
	}
	wg.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
}
