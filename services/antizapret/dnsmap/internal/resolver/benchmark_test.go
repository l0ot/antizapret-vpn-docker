package resolver

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
)

type benchmarkDoH struct{ response *dns.Msg }

func (d benchmarkDoH) Query(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, error) {
	return d.response.Copy(), nil
}

func BenchmarkAWithExistingMapping(b *testing.B) {
	request := question("example.com", dns.TypeA)
	upstream := answer(request, dns.RcodeSuccess, "192.0.2.1")
	mapper := &fakeMapper{mappings: map[string]string{"192.0.2.1": "14.16.0.2"}}
	proxy := New(benchmarkDoH{response: upstream}, &fakeMatcher{matches: map[string]bool{}}, mapper, "az-local", "az-resolver", nil)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		response := proxy.Resolve(context.Background(), request)
		if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != net.ParseIP("14.16.0.2").String() {
			b.Fatal("unexpected benchmark response")
		}
	}
}
