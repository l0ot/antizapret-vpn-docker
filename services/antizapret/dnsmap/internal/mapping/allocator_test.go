package mapping

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"dnsmap/internal/firewall"
)

type runner struct {
	mu       sync.Mutex
	commands [][]string
	errors   []error
}

func (r *runner) Run(_ context.Context, args ...string) (firewall.Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.commands = append(r.commands, append([]string(nil), args...))
	if len(r.errors) == 0 {
		return firewall.Result{}, nil
	}
	err := r.errors[0]
	r.errors = r.errors[1:]
	return firewall.Result{Stderr: []byte("fake iptables error")}, err
}

func newManager(t testing.TB, prefix string, r *runner) *Manager {
	t.Helper()
	m, err := New(prefix, firewall.Firewall{Runner: r, Chain: "dnsmap"})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAllocatorReservesFirstUsableAndAllocatesSequentially(t *testing.T) {
	r := &runner{}
	m := newManager(t, "14.16.0.0/29", r)
	for i, want := range []string{"14.16.0.2", "14.16.0.3", "14.16.0.4"} {
		got, err := m.Add(context.Background(), net.ParseIP("192.0.2."+string(rune('1'+i))))
		if err != nil || got.String() != want {
			t.Fatalf("mapping %d = %v, %v; want %s", i, got, err, want)
		}
	}
	if _, ok := m.Get(net.ParseIP("192.0.2.1")); !ok {
		t.Fatal("existing mapping was not returned")
	}
}

func TestSmallPrefixes(t *testing.T) {
	if _, err := New("14.16.0.0/31", firewall.Firewall{Runner: &runner{}, Chain: "dnsmap"}); err == nil {
		t.Fatal("/31 unexpectedly has a mapping address")
	}
	if _, err := New("14.16.0.0/32", firewall.Firewall{Runner: &runner{}, Chain: "dnsmap"}); err == nil {
		t.Fatal("/32 unexpectedly has a mapping address")
	}
	m := newManager(t, "14.16.0.0/30", &runner{})
	got, err := m.Add(context.Background(), net.ParseIP("192.0.2.1"))
	if err != nil || got.String() != "14.16.0.2" {
		t.Fatalf("/30 mapping = %v, %v", got, err)
	}
}

func TestConcurrentSameRealAddressCreatesOneRule(t *testing.T) {
	r := &runner{}
	m := newManager(t, "14.16.0.0/29", r)
	var wg sync.WaitGroup
	results := make([]string, 100)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			fake, err := m.Add(context.Background(), net.ParseIP("192.0.2.1"))
			if err != nil {
				results[i] = err.Error()
				return
			}
			results[i] = fake.String()
		}(i)
	}
	wg.Wait()
	for _, result := range results {
		if result != "14.16.0.2" {
			t.Fatalf("unexpected concurrent result %q", result)
		}
	}
	if len(r.commands) != 1 {
		t.Fatalf("expected one iptables add, got %d", len(r.commands))
	}
}

func TestIptablesFailureRollsBackAndReusesAddress(t *testing.T) {
	r := &runner{errors: []error{errors.New("add failed")}}
	m := newManager(t, "14.16.0.0/29", r)
	if _, err := m.Add(context.Background(), net.ParseIP("192.0.2.1")); err == nil {
		t.Fatal("failed iptables add was accepted")
	}
	if len(m.Snapshot()) != 0 {
		t.Fatal("failed add changed internal mapping")
	}
	fake, err := m.Add(context.Background(), net.ParseIP("192.0.2.1"))
	if err != nil || fake.String() != "14.16.0.2" {
		t.Fatalf("address was not returned to pool: %v, %v", fake, err)
	}
}

func TestExhaustionFlushesBeforeReusingRange(t *testing.T) {
	r := &runner{}
	m := newManager(t, "14.16.0.0/30", r)
	if _, err := m.Add(context.Background(), net.ParseIP("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(context.Background(), net.ParseIP("192.0.2.2")); err != nil {
		t.Fatal(err)
	}
	if len(r.commands) != 3 || r.commands[1][3] != "-F" {
		t.Fatalf("expected add, flush, add command sequence: %#v", r.commands)
	}
	if got := m.Snapshot()["192.0.2.2"]; got != "14.16.0.2" {
		t.Fatalf("mapping after flush = %q", got)
	}
}

func TestFailedFlushPreservesMappings(t *testing.T) {
	r := &runner{errors: []error{nil, errors.New("flush failed")}}
	m := newManager(t, "14.16.0.0/30", r)
	if _, err := m.Add(context.Background(), net.ParseIP("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(context.Background(), net.ParseIP("192.0.2.2")); err == nil {
		t.Fatal("failed flush was accepted")
	}
	if got := m.Snapshot()["192.0.2.1"]; got != "14.16.0.2" {
		t.Fatalf("old mapping was lost after failed flush: %q", got)
	}
}

func TestRestoreValidatesConflictsAndExcludesPool(t *testing.T) {
	m := newManager(t, "14.16.0.0/29", &runner{})
	if err := m.Restore(net.ParseIP("192.0.2.1"), net.ParseIP("14.16.0.4")); err != nil {
		t.Fatal(err)
	}
	if err := m.Restore(net.ParseIP("192.0.2.2"), net.ParseIP("14.16.0.4")); err == nil {
		t.Fatal("conflicting fake address accepted")
	}
	if err := m.Restore(net.ParseIP("192.0.2.1"), net.ParseIP("14.16.0.5")); err == nil {
		t.Fatal("conflicting real address accepted")
	}
	fake, err := m.Add(context.Background(), net.ParseIP("192.0.2.3"))
	if err != nil || fake.String() != "14.16.0.2" {
		t.Fatalf("restore incorrectly changed sequential pool: %v, %v", fake, err)
	}
	if err := m.Restore(net.ParseIP("192.0.2.9"), net.ParseIP("14.17.0.2")); err == nil {
		t.Fatal("out-of-range fake address accepted")
	}
}

func BenchmarkExistingMapping(b *testing.B) {
	m := newManager(b, "14.16.0.0/15", &runner{})
	if _, err := m.Add(context.Background(), net.ParseIP("192.0.2.1")); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = m.Get(net.ParseIP("192.0.2.1"))
	}
}
