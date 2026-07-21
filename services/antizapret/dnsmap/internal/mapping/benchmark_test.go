package mapping

import (
	"context"
	"net"
	"testing"

	"dnsmap/internal/firewall"
)

func BenchmarkNewMapping(b *testing.B) {
	m, err := New("14.0.0.0/8", firewall.Firewall{Runner: &runner{}, Chain: "dnsmap"})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		real := net.IPv4(198, 51, byte(i>>8), byte(i))
		if _, err := m.Add(context.Background(), real); err != nil {
			b.Fatal(err)
		}
	}
}
