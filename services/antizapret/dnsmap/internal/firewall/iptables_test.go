package firewall

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeRunner struct {
	commands [][]string
	results  []struct {
		result Result
		err    error
	}
}

func (r *fakeRunner) Run(_ context.Context, args ...string) (Result, error) {
	r.commands = append(r.commands, append([]string(nil), args...))
	if len(r.results) == 0 {
		return Result{}, nil
	}
	result := r.results[0]
	r.results = r.results[1:]
	return result.result, result.err
}

func TestParseRulesSupportsToVariantsAndRejectsInvalid(t *testing.T) {
	rules, err := ParseRules([]byte("-N dnsmap\n-A dnsmap -d 14.16.0.2/32 -j DNAT --to 192.0.2.1\n-A dnsmap -d 14.16.0.3 -j DNAT --to-destination 192.0.2.2\n"), "dnsmap")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Fake.String() != "14.16.0.2" || rules[1].Real.String() != "192.0.2.2" {
		t.Fatalf("unexpected parsed rules: %#v", rules)
	}
	for _, input := range []string{
		"-A other -d 14.16.0.2 -j DNAT --to 192.0.2.1\n",
		"-A dnsmap -d 2001:db8::1 -j DNAT --to 192.0.2.1\n",
		"-A dnsmap -d 14.16.0.2 -j DNAT --to 192.0.2.1-192.0.2.2\n",
	} {
		if _, err := ParseRules([]byte(input), "dnsmap"); err == nil {
			t.Fatalf("ParseRules accepted invalid rule %q", input)
		}
	}
}

func TestFuzzableRulesParser(t *testing.T) {
	for _, input := range []string{"", "garbage", "-A dnsmap -d 14.16.0.2 -j DNAT --to 192.0.2.1"} {
		_, _ = ParseRules([]byte(input), "dnsmap")
	}
}

func FuzzParseRules(f *testing.F) {
	f.Add("-A dnsmap -d 14.16.0.2 -j DNAT --to 192.0.2.1\n")
	f.Fuzz(func(_ *testing.T, input string) { _, _ = ParseRules([]byte(input), "dnsmap") })
}

func TestFirewallCommandsUseSeparateArguments(t *testing.T) {
	runner := &fakeRunner{}
	fw := Firewall{Runner: runner, Chain: "dnsmap"}
	if err := fw.Add(context.Background(), net.ParseIP("14.16.0.2"), net.ParseIP("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || strings.Join(runner.commands[0], " ") != "-w -t nat -A dnsmap -d 14.16.0.2 -j DNAT --to 192.0.2.1" {
		t.Fatalf("unexpected command: %#v", runner.commands[0])
	}
}

func TestFirewallErrorIncludesStderr(t *testing.T) {
	runner := &fakeRunner{results: []struct {
		result Result
		err    error
	}{{result: Result{Stderr: []byte("permission denied")}, err: errors.New("exit status 1")}}}
	err := (Firewall{Runner: runner, Chain: "dnsmap"}).Flush(context.Background())
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("unexpected error: %v", err)
	}
}
