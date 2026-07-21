package asn

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type testDatabase struct {
	mu      sync.RWMutex
	records map[string]Record
	err     error
}

func (d *testDatabase) Lookup(address string) (Record, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.err != nil {
		return Record{}, d.err
	}
	return d.records[address], nil
}
func (d *testDatabase) Close() error { return nil }

func TestParseFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.txt")
	content := "AS13335 # Cloudflare\n13238\nAS13335\nTelegram Messenger, Inc.\n/\\bg-?core\\b/\n/gcore\n\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules.ASN) != 2 || rules.ASN[13335] != "AS13335" || rules.ASN[13238] != "13238" {
		t.Fatalf("unexpected ASN rules: %#v", rules.ASN)
	}
	if len(rules.Substrings) != 2 || rules.Substrings[0].Text != "Telegram Messenger, Inc." || rules.Substrings[1].Text != "/gcore" {
		t.Fatalf("unexpected substring rules: %#v", rules.Substrings)
	}
	if len(rules.Regexes) != 1 || rules.Regexes[0].Text != "/\\bg-?core\\b/" {
		t.Fatalf("unexpected regex rules: %#v", rules.Regexes)
	}
}

func TestMatcherOrderAndUnicode(t *testing.T) {
	db := &testDatabase{records: map[string]Record{
		"192.0.2.1": {ASN: 13335, Organization: "Telegram Cloudflare"},
		"192.0.2.2": {ASN: 62041, Organization: "ТЕЛЕГРАМ LLC"},
		"192.0.2.3": {ASN: 64500, Organization: "G-Core Labs S.A."},
		"192.0.2.4": {ASN: 64500, Organization: "Edgecore Networks"},
		"192.0.2.5": {ASN: 13238, Organization: "Яндекс LLC"},
	}}
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.txt")
	if err := os.WriteFile(path, []byte("AS13335\nтелеграм\n/\\bg-?core\\b/\n/яндекс/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m, _, _, err := NewMatcher(path, db)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		ip   string
		rule string
	}{
		{name: "exact ASN wins", ip: "192.0.2.1", rule: "AS13335"},
		{name: "unicode substring", ip: "192.0.2.2", rule: "телеграм"},
		{name: "unicode regex boundary", ip: "192.0.2.3", rule: "/\\bg-?core\\b/"},
		{name: "regex Unicode", ip: "192.0.2.5", rule: "/яндекс/"},
	} {
		t.Run(test.name, func(t *testing.T) {
			match, ok, err := m.Match(test.ip)
			if err != nil || !ok || match.Rule != test.rule {
				t.Fatalf("Match(%s) = %#v, %v, %v", test.ip, match, ok, err)
			}
		})
	}
	if _, ok, err := m.Match("192.0.2.4"); err != nil || ok {
		t.Fatalf("word boundary incorrectly matched: ok=%v err=%v", ok, err)
	}
}

func TestMalformedRegexAndAtomicReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.txt")
	if err := os.WriteFile(path, []byte("AS13335\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := &testDatabase{records: map[string]Record{"192.0.2.1": {ASN: 13335}}}
	m, _, _, err := NewMatcher(path, db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("AS13238\n/[/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Reload(); err == nil {
		t.Fatal("Reload accepted malformed regex")
	}
	if _, ok, err := m.Match("192.0.2.1"); err != nil || !ok {
		t.Fatalf("last-known-good rules were lost: ok=%v err=%v", ok, err)
	}
	if err := os.WriteFile(path, []byte("13238\nYandex\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Reload(); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentLookupAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asn.txt")
	if err := os.WriteFile(path, []byte("AS13335\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db := &testDatabase{records: map[string]Record{"192.0.2.1": {ASN: 13335}}}
	m, _, _, err := NewMatcher(path, db)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _, _ = m.Match("192.0.2.1")
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if _, _, err := m.Reload(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func FuzzParseFile(f *testing.F) {
	f.Add("AS13335 # comment\nTelegram\n")
	f.Add("/gcore\n")
	f.Fuzz(func(t *testing.T, input string) {
		path := filepath.Join(t.TempDir(), "asn.txt")
		if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = ParseFile(path)
	})
}

func BenchmarkMatcherLookup(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "asn.txt")
	if err := os.WriteFile(path, []byte("AS13335\nTelegram\n/gcore/\n"), 0o644); err != nil {
		b.Fatal(err)
	}
	db := &testDatabase{records: map[string]Record{"192.0.2.1": {ASN: 13335, Organization: "Cloudflare"}}}
	m, _, _, err := NewMatcher(path, db)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _ = m.Match("192.0.2.1")
	}
}
