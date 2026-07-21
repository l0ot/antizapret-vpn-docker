package firewall

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type Result struct {
	Stdout []byte
	Stderr []byte
}

type Runner interface {
	Run(ctx context.Context, args ...string) (Result, error)
}

type CommandRunner struct{ Binary string }

func (r CommandRunner) Run(ctx context.Context, args ...string) (Result, error) {
	binary := r.Binary
	if binary == "" {
		binary = "iptables"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, fmt.Errorf("run %s: %w", binary, err)
	}
	return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

type Rule struct {
	Chain string
	Fake  net.IP
	Real  net.IP
}

type Firewall struct {
	Runner Runner
	Chain  string
}

func (f Firewall) List(ctx context.Context) ([]Rule, error) {
	result, err := f.Runner.Run(ctx, "-w", "-t", "nat", "-S", f.Chain)
	if err != nil {
		return nil, fmt.Errorf("list iptables chain %s: %w", f.Chain, err)
	}
	return ParseRules(result.Stdout, f.Chain)
}

func (f Firewall) Add(ctx context.Context, fake, real net.IP) error {
	result, err := f.Runner.Run(ctx, "-w", "-t", "nat", "-A", f.Chain,
		"-d", fake.String(), "-j", "DNAT", "--to", real.String())
	if err != nil {
		stderr := strings.TrimSpace(string(result.Stderr))
		if stderr != "" {
			return fmt.Errorf("add DNAT mapping %s to %s: %w: %s", fake, real, err, stderr)
		}
		return fmt.Errorf("add DNAT mapping %s to %s: %w", fake, real, err)
	}
	return nil
}

func (f Firewall) Flush(ctx context.Context) error {
	result, err := f.Runner.Run(ctx, "-w", "-t", "nat", "-F", f.Chain)
	if err != nil {
		stderr := strings.TrimSpace(string(result.Stderr))
		if stderr != "" {
			return fmt.Errorf("flush iptables chain %s: %w: %s", f.Chain, err, stderr)
		}
		return fmt.Errorf("flush iptables chain %s: %w", f.Chain, err)
	}
	return nil
}

func ParseRules(output []byte, chain string) ([]Rule, error) {
	var rules []Rule
	for lineNumber, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "-N" && fields[1] == chain {
			continue
		}
		if len(fields) < 2 || fields[0] != "-A" || fields[1] != chain {
			return nil, fmt.Errorf("invalid iptables rule on line %d: expected -A %s", lineNumber+1, line)
		}
		var fake, real string
		for i := 2; i < len(fields); i++ {
			switch fields[i] {
			case "-d":
				if i+1 >= len(fields) {
					return nil, fmt.Errorf("missing destination on iptables line %d", lineNumber+1)
				}
				fake = fields[i+1]
				i++
			case "--to", "--to-destination":
				if i+1 >= len(fields) {
					return nil, fmt.Errorf("missing DNAT destination on iptables line %d", lineNumber+1)
				}
				real = fields[i+1]
				i++
			}
		}
		fakeIP, err := parseIPv4Token(fake)
		if err != nil {
			return nil, fmt.Errorf("invalid fake IP on iptables line %d: %w", lineNumber+1, err)
		}
		realIP, err := parseIPv4Token(real)
		if err != nil {
			return nil, fmt.Errorf("invalid real IP on iptables line %d: %w", lineNumber+1, err)
		}
		rules = append(rules, Rule{Chain: chain, Fake: fakeIP, Real: realIP})
	}
	return rules, nil
}

func parseIPv4Token(value string) (net.IP, error) {
	value = strings.TrimSpace(value)
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		if value[slash:] != "/32" {
			return nil, fmt.Errorf("IPv4 prefix must be /32: %q", value)
		}
		value = value[:slash]
	}
	if dash := strings.IndexByte(value, '-'); dash >= 0 {
		return nil, fmt.Errorf("address ranges are not supported: %q", value)
	}
	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("not an IPv4 address: %q", value)
	}
	return ip.To4(), nil
}
