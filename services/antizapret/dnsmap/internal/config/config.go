package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultPort           = 53
	DefaultDoHPort        = 3000
	DefaultTimeout        = 5 * time.Second
	DefaultFakeIPRange    = "14.16.0.0/16"
	DefaultResolverClient = "az-resolver"
	DefaultASNFile        = "/root/antizapret/result/asn.txt"
	DefaultASNDatabase    = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"
)

// Config is the complete runtime configuration of dnsmap.
type Config struct {
	Port             int
	Address          string
	Upstream         string
	UpstreamHost     string
	UpstreamPort     int
	DoHPort          int
	TCP              bool
	Timeout          time.Duration
	Passthrough      bool
	Log              string
	LogPrefix        bool
	IPRange          string
	ClientID         string
	ResolverClientID string
	ASNFile          string
	ASNDatabase      string
}

func Parse(args []string, env func(string) string) (Config, error) {
	defaultDNS := env("DNS")
	if defaultDNS == "" {
		defaultDNS = "127.0.0.1"
	}
	client := env("CLIENT")
	if client == "" {
		client = "az-local"
	}
	defaultHost, defaultPort, parseDNSErr := ParseHostPort(defaultDNS)
	if parseDNSErr != nil {
		return Config{}, fmt.Errorf("invalid DNS environment value: %w", parseDNSErr)
	}
	upstream := net.JoinHostPort(defaultHost, strconv.Itoa(defaultPort))

	fs := flag.NewFlagSet("dnsmap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg Config
	fs.IntVar(&cfg.Port, "port", DefaultPort, "Local proxy port (default: 53)")
	fs.IntVar(&cfg.Port, "p", DefaultPort, "Local proxy port (default: 53)")
	fs.StringVar(&cfg.Address, "address", "", "Local proxy listen address (default: all)")
	fs.StringVar(&cfg.Address, "a", "", "Local proxy listen address (default: all)")
	fs.StringVar(&cfg.Upstream, "upstream", upstream, "Upstream DNS server:port")
	fs.StringVar(&cfg.Upstream, "u", upstream, "Upstream DNS server:port")
	fs.IntVar(&cfg.DoHPort, "doh-port", DefaultDoHPort, "AdGuard unencrypted DNS-over-HTTPS port")
	fs.BoolVar(&cfg.TCP, "tcp", false, "TCP proxy (default: UDP only)")
	var timeoutSeconds float64
	fs.Float64Var(&timeoutSeconds, "timeout", DefaultTimeout.Seconds(), "Upstream timeout in seconds")
	fs.Float64Var(&timeoutSeconds, "o", DefaultTimeout.Seconds(), "Upstream timeout in seconds")
	fs.BoolVar(&cfg.Passthrough, "passthrough", false, "Forward DNS packets without decoding them")
	fs.StringVar(&cfg.Log, "log", "request,reply,truncated,error", "Log hooks to enable")
	fs.BoolVar(&cfg.LogPrefix, "log-prefix", false, "Log prefix (timestamp/handler/resolver)")
	fs.StringVar(&cfg.IPRange, "iprange", DefaultFakeIPRange, "Fake IP range")
	fs.StringVar(&cfg.ClientID, "client-id", client, "AdGuard client ID used for filtered requests")
	fs.StringVar(&cfg.ResolverClientID, "resolver-client-id", DefaultResolverClient, "AdGuard client ID used to resolve SERVFAIL responses")
	fs.StringVar(&cfg.ASNFile, "asn-file", DefaultASNFile, "Blocked ASN numbers and organization names")
	fs.StringVar(&cfg.ASNDatabase, "asn-database", DefaultASNDatabase, "MaxMind ASN database")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	cfg.Timeout = time.Duration(timeoutSeconds * float64(time.Second))
	if err := validate(&cfg); err != nil {
		return Config{}, err
	}
	host, port, parseErr := ParseHostPort(cfg.Upstream)
	cfg.UpstreamHost, cfg.UpstreamPort = host, port
	if parseErr != nil {
		return Config{}, fmt.Errorf("invalid upstream: %w", parseErr)
	}
	return cfg, nil
}

func validate(cfg *Config) error {
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	if cfg.DoHPort < 1 || cfg.DoHPort > 65535 {
		return fmt.Errorf("doh-port must be between 1 and 65535")
	}
	if cfg.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}
	if strings.TrimSpace(cfg.ClientID) == "" || strings.TrimSpace(cfg.ResolverClientID) == "" {
		return fmt.Errorf("client IDs must not be empty")
	}
	return nil
}

// ParseHostPort accepts host, host:port and bracketed IPv6 host:port forms.
func ParseHostPort(value string) (string, int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		parsed, parseErr := strconv.Atoi(port)
		if parseErr != nil || parsed < 1 || parsed > 65535 {
			return "", 0, fmt.Errorf("invalid port %q", port)
		}
		return host, parsed, nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"), 53, nil
	}
	if strings.Count(value, ":") == 1 {
		host, port, ok := strings.Cut(value, ":")
		if ok {
			parsed, err := strconv.Atoi(port)
			if err != nil || parsed < 1 || parsed > 65535 {
				return "", 0, fmt.Errorf("invalid port %q", port)
			}
			return host, parsed, nil
		}
	}
	return strings.Trim(value, "[]"), 53, nil
}
