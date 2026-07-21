package config

import "testing"

func TestParseDefaultsAndAliases(t *testing.T) {
	cfg, err := Parse([]string{"-p", "5353", "-a", "127.0.0.1", "-u", "[::1]:54", "-o", "1.5"}, func(key string) string {
		if key == "DNS" {
			return "adguard"
		}
		if key == "CLIENT" {
			return "custom-client"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 5353 || cfg.Address != "127.0.0.1" || cfg.UpstreamHost != "::1" || cfg.UpstreamPort != 54 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.ClientID != "custom-client" || cfg.Timeout.String() != "1.5s" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		name string
		in   string
		host string
		port int
	}{
		{name: "hostname", in: "adguard", host: "adguard", port: 53},
		{name: "ipv4", in: "127.0.0.1:5353", host: "127.0.0.1", port: 5353},
		{name: "ipv6", in: "[::1]:5353", host: "::1", port: 5353},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := ParseHostPort(tt.in)
			if err != nil || host != tt.host || port != tt.port {
				t.Fatalf("ParseHostPort(%q) = %q:%d, %v", tt.in, host, port, err)
			}
		})
	}
}
