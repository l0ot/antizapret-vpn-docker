package resolver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"dnsmap/internal/asn"
	"github.com/miekg/dns"
)

type DoHClient interface {
	Query(ctx context.Context, request *dns.Msg, clientID string) (*dns.Msg, error)
}

type ASNMatcher interface {
	Match(address string) (asn.Match, bool, error)
}

type Mapper interface {
	Get(real net.IP) (net.IP, bool)
	Add(ctx context.Context, real net.IP) (net.IP, error)
}

// Resolver implements the legacy resolver decision tree while
// keeping all external operations behind interfaces for deterministic tests.
type Resolver struct {
	doh              DoHClient
	matcher          ASNMatcher
	mapper           Mapper
	clientID         string
	resolverClientID string
	logger           *slog.Logger
	errorLog         *errorLimiter
}

type errorLimiter struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
	now        func() time.Time
}

func New(doh DoHClient, matcher ASNMatcher, mapper Mapper, clientID, resolverClientID string, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Resolver{
		doh: doh, matcher: matcher, mapper: mapper,
		clientID: clientID, resolverClientID: resolverClientID,
		logger:   logger,
		errorLog: &errorLimiter{now: time.Now},
	}
}

func (r *Resolver) Resolve(ctx context.Context, request *dns.Msg) *dns.Msg {
	if len(request.Question) == 0 {
		return r.fail(request, fmt.Errorf("DNS request has no question"))
	}
	reply, err := r.doh.Query(ctx, request, r.clientID)
	if err != nil {
		return r.fail(request, err)
	}

	qtype := request.Question[0].Qtype
	if qtype == dns.TypeAAAA || qtype == dns.TypeHTTPS {
		return emptyReply(request)
	}
	if qtype != dns.TypeA {
		return reply
	}
	if reply.Rcode == dns.RcodeServerFailure {
		initial := reply
		resolved, queryErr := r.doh.Query(ctx, request, r.resolverClientID)
		if queryErr != nil {
			return r.fail(request, queryErr)
		}
		matched := false
		for _, rr := range resolved.Answer {
			a, ok := rr.(*dns.A)
			if !ok {
				continue
			}
			result, isMatch, matchErr := r.matcher.Match(a.A.String())
			if matchErr != nil {
				return r.fail(request, matchErr)
			}
			if isMatch {
				r.logger.Info("ASN match", "ip", result.Address, "asn", result.ASN, "organization", result.Organization, "rule", result.Rule)
				matched = true
				break
			}
		}
		if !matched {
			return initial
		}
		reply = resolved
	}
	if err := r.rewriteAnswers(ctx, request, reply); err != nil {
		return r.fail(request, err)
	}
	return reply
}

func (r *Resolver) rewriteAnswers(ctx context.Context, request, reply *dns.Msg) error {
	qname := request.Question[0].Name
	answers := make([]dns.RR, 0, len(reply.Answer))
	for _, rr := range reply.Answer {
		if rr.Header().Rrtype == dns.TypeCNAME {
			continue
		}
		a, ok := rr.(*dns.A)
		if !ok {
			answers = append(answers, rr)
			continue
		}
		fake, exists := r.mapper.Get(a.A)
		if !exists {
			var err error
			fake, err = r.mapper.Add(ctx, a.A)
			if err != nil {
				return err
			}
		}
		copyA := *a
		copyA.Hdr.Name = qname
		copyA.Hdr.Ttl = 300
		copyA.A = fake.To4()
		answers = append(answers, &copyA)
	}
	reply.Answer = answers
	return nil
}

func emptyReply(request *dns.Msg) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Rcode = dns.RcodeSuccess
	response.Answer = nil
	response.Ns = nil
	response.Extra = nil
	return response
}

func (r *Resolver) fail(request *dns.Msg, err error) *dns.Msg {
	r.logProcessingError(err)
	response := new(dns.Msg)
	response.SetReply(request)
	response.Rcode = dns.RcodeServerFailure
	response.Answer = nil
	response.Ns = nil
	response.Extra = nil
	return response
}

func (r *Resolver) logProcessingError(err error) {
	now := r.errorLog.now()
	r.errorLog.mu.Lock()
	if !r.errorLog.last.IsZero() && now.Sub(r.errorLog.last) < 5*time.Second {
		r.errorLog.suppressed++
		r.errorLog.mu.Unlock()
		return
	}
	suppressed := r.errorLog.suppressed
	r.errorLog.suppressed = 0
	r.errorLog.last = now
	r.errorLog.mu.Unlock()
	if suppressed > 0 {
		r.logger.Error("DNS request processing failed", "error", err, "similar_errors_suppressed", suppressed)
		return
	}
	r.logger.Error("DNS request processing failed", "error", err)
}
