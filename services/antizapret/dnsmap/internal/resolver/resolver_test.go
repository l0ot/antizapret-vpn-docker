package resolver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"dnsmap/internal/asn"
	"github.com/miekg/dns"
)

type fakeDoH struct {
	mu        sync.Mutex
	responses []*dns.Msg
	ids       []string
	errors    []error
}

func (d *fakeDoH) Query(_ context.Context, _ *dns.Msg, clientID string) (*dns.Msg, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ids = append(d.ids, clientID)
	if len(d.errors) > 0 {
		err := d.errors[0]
		d.errors = d.errors[1:]
		return nil, err
	}
	response := d.responses[0]
	d.responses = d.responses[1:]
	return response, nil
}

type fakeMatcher struct {
	mu      sync.Mutex
	matches map[string]bool
	err     error
	lookups []string
}

func (m *fakeMatcher) Match(address string) (asn.Match, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lookups = append(m.lookups, address)
	if m.err != nil {
		return asn.Match{}, false, m.err
	}
	return asn.Match{Address: address, ASN: 13335, Organization: "Cloudflare", Rule: "AS13335"}, m.matches[address], nil
}

type fakeMapper struct {
	mu       sync.Mutex
	mappings map[string]string
	err      error
	adds     []string
}

func (m *fakeMapper) Get(real net.IP) (net.IP, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fake, ok := m.mappings[real.String()]
	if !ok {
		return nil, false
	}
	return net.ParseIP(fake), true
}

func (m *fakeMapper) Add(_ context.Context, real net.IP) (net.IP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.adds = append(m.adds, real.String())
	if m.err != nil {
		return nil, m.err
	}
	fake := net.ParseIP("14.16.0." + string(rune('2'+len(m.adds)-1)))
	m.mappings[real.String()] = fake.String()
	return fake, nil
}

func question(name string, qtype uint16) *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Id: 7, RecursionDesired: true}, Question: []dns.Question{{Name: dns.Fqdn(name), Qtype: qtype, Qclass: dns.ClassINET}}}
}

func answer(request *dns.Msg, rcode int, addresses ...string) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(request)
	msg.Rcode = rcode
	for _, address := range addresses {
		msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(address).To4()})
	}
	return msg
}

func newResolver(dohClient *fakeDoH, matcher *fakeMatcher, mapper *fakeMapper) *Resolver {
	return New(dohClient, matcher, mapper, "az-local", "az-resolver", slog.Default())
}

func TestAResponseMappingAndRecordShape(t *testing.T) {
	request := question("example.com", dns.TypeA)
	reply := answer(request, dns.RcodeSuccess, "192.0.2.1")
	reply.Answer = append([]dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "target.example."}}, reply.Answer...)
	dohClient := &fakeDoH{responses: []*dns.Msg{reply}}
	matcher := &fakeMatcher{matches: map[string]bool{}}
	mapper := &fakeMapper{mappings: map[string]string{"192.0.2.1": "14.16.0.2"}}
	response := newResolver(dohClient, matcher, mapper).Resolve(context.Background(), request)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("unexpected response: %s", response)
	}
	a, ok := response.Answer[0].(*dns.A)
	if !ok || a.A.String() != "14.16.0.2" || a.Hdr.Name != request.Question[0].Name || a.Hdr.Ttl != 300 {
		t.Fatalf("unexpected mapped answer: %#v", response.Answer[0])
	}
	if len(matcher.lookups) != 0 {
		t.Fatal("ASN lookup was used for a non-SERVFAIL response")
	}
}

func TestSERVFAILUsesResolverIDAndMapsAllAddressesAfterOneMatch(t *testing.T) {
	request := question("example.com", dns.TypeA)
	dohClient := &fakeDoH{responses: []*dns.Msg{answer(request, dns.RcodeServerFailure), answer(request, dns.RcodeSuccess, "192.0.2.1", "192.0.2.2")}}
	matcher := &fakeMatcher{matches: map[string]bool{"192.0.2.1": false, "192.0.2.2": true}}
	mapper := &fakeMapper{mappings: map[string]string{}}
	response := newResolver(dohClient, matcher, mapper).Resolve(context.Background(), request)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 2 {
		t.Fatalf("unexpected SERVFAIL fallback response: %s", response)
	}
	if len(dohClient.ids) != 2 || dohClient.ids[0] != "az-local" || dohClient.ids[1] != "az-resolver" {
		t.Fatalf("unexpected client IDs: %#v", dohClient.ids)
	}
	if len(mapper.adds) != 2 {
		t.Fatalf("expected all A records to be mapped, got %#v", mapper.adds)
	}
}

func TestSERVFAILNXDomainAndEmptyResponsesArePreserved(t *testing.T) {
	request := question("example.com", dns.TypeA)
	for _, test := range []struct {
		name string
		msg  *dns.Msg
	}{
		{name: "servfail no match", msg: answer(request, dns.RcodeServerFailure)},
		{name: "nxdomain", msg: answer(request, dns.RcodeNameError)},
		{name: "empty noerror", msg: answer(request, dns.RcodeSuccess)},
	} {
		t.Run(test.name, func(t *testing.T) {
			responses := []*dns.Msg{test.msg}
			if test.msg.Rcode == dns.RcodeServerFailure {
				responses = append(responses, answer(request, dns.RcodeSuccess, "192.0.2.1"))
			}
			dohClient := &fakeDoH{responses: responses}
			matcher := &fakeMatcher{matches: map[string]bool{}}
			mapper := &fakeMapper{mappings: map[string]string{}}
			response := newResolver(dohClient, matcher, mapper).Resolve(context.Background(), request)
			if response.Rcode != test.msg.Rcode || len(response.Answer) != 0 {
				t.Fatalf("response changed: rcode=%d answers=%d", response.Rcode, len(response.Answer))
			}
		})
	}
}

func TestAAAAHTTPSSuppressedAndOtherTypesPassThrough(t *testing.T) {
	for _, qtype := range []uint16{dns.TypeAAAA, dns.TypeHTTPS} {
		request := question("example.com", qtype)
		response := newResolver(&fakeDoH{responses: []*dns.Msg{answer(request, dns.RcodeSuccess, "192.0.2.1")}}, &fakeMatcher{}, &fakeMapper{mappings: map[string]string{}}).Resolve(context.Background(), request)
		if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 {
			t.Fatalf("qtype %d was not suppressed", qtype)
		}
	}
	request := question("example.com", dns.TypeMX)
	upstream := answer(request, dns.RcodeSuccess, "192.0.2.1")
	response := newResolver(&fakeDoH{responses: []*dns.Msg{upstream}}, &fakeMatcher{}, &fakeMapper{mappings: map[string]string{}}).Resolve(context.Background(), request)
	if len(response.Answer) != 1 {
		t.Fatal("non-A response was unexpectedly changed")
	}
}

func TestLookupAndMappingErrorsReturnSERVFAIL(t *testing.T) {
	request := question("example.com", dns.TypeA)
	for _, test := range []struct {
		name      string
		matcher   *fakeMatcher
		mapper    *fakeMapper
		responses []*dns.Msg
	}{
		{name: "MMDB", matcher: &fakeMatcher{err: errors.New("MMDB failed")}, mapper: &fakeMapper{mappings: map[string]string{}}, responses: []*dns.Msg{answer(request, dns.RcodeServerFailure), answer(request, dns.RcodeSuccess, "192.0.2.1")}},
		{name: "mapping", matcher: &fakeMatcher{matches: map[string]bool{"192.0.2.1": true}}, mapper: &fakeMapper{mappings: map[string]string{}, err: errors.New("iptables failed")}, responses: []*dns.Msg{answer(request, dns.RcodeSuccess, "192.0.2.1")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := newResolver(&fakeDoH{responses: test.responses}, test.matcher, test.mapper).Resolve(context.Background(), request)
			if response.Rcode != dns.RcodeServerFailure {
				t.Fatalf("got rcode %d", response.Rcode)
			}
		})
	}
}

func TestErrorLoggingIsRateLimited(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, nil))
	r := New(&fakeDoH{errors: []error{errors.New("first")}}, &fakeMatcher{}, &fakeMapper{mappings: map[string]string{}}, "a", "b", logger)
	current := time.Unix(10, 0)
	r.errorLog.now = func() time.Time { return current }
	request := question("example.com", dns.TypeA)
	_ = r.Resolve(context.Background(), request)
	_ = r.fail(request, errors.New("second"))
	if strings.Count(output.String(), "DNS request processing failed") != 1 || r.errorLog.suppressed != 1 {
		t.Fatalf("rate limiter output=%q suppressed=%d", output.String(), r.errorLog.suppressed)
	}
}
