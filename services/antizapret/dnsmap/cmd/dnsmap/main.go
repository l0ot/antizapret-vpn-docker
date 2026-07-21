package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"dnsmap/internal/asn"
	"dnsmap/internal/config"
	"dnsmap/internal/dnsserver"
	"dnsmap/internal/doh"
	"dnsmap/internal/firewall"
	"dnsmap/internal/mapping"
	"dnsmap/internal/resolver"
)

const startedFlag = "/tmp/.dns_started"

func main() {
	_ = os.Remove(startedFlag)
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "dnsmap: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Parse(args, os.Getenv)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("invalid configuration: %w", err)
	}
	logger := newLogger(cfg.LogPrefix)
	logger.Info("starting DNS proxy", "listen_address", displayAddress(cfg.Address), "port", cfg.Port,
		"upstream", cfg.Upstream, "transport", transport(cfg.TCP), "passthrough", cfg.Passthrough)

	database, err := asn.OpenDatabase(cfg.ASNDatabase)
	if err != nil {
		return err
	}
	defer database.Close()
	matcher, asnCount, organizationCount, err := asn.NewMatcher(cfg.ASNFile, database)
	if err != nil {
		return err
	}
	logger.Info("loaded ASN rules", "asn_numbers", asnCount, "organization_rules", organizationCount)

	runner := firewall.CommandRunner{}
	fw := firewall.Firewall{Runner: runner, Chain: "dnsmap"}
	allocator, err := mapping.New(cfg.IPRange, fw)
	if err != nil {
		return err
	}
	initialMappings, err := fw.List(context.Background())
	if err != nil {
		return err
	}
	for _, rule := range initialMappings {
		if err := allocator.Restore(rule.Real, rule.Fake); err != nil {
			logger.Error("ignoring invalid restored mapping", "fake_ip", rule.Fake, "real_ip", rule.Real, "error", err)
			continue
		}
		logger.Info("restored mapping", "fake_ip", rule.Fake, "real_ip", rule.Real)
	}

	dohClient := doh.New(cfg.UpstreamHost, cfg.DoHPort, cfg.Timeout)
	proxyResolver := resolver.New(dohClient, matcher, allocator, cfg.ClientID, cfg.ResolverClientID, logger)
	server := dnsserver.New(cfg.Address, cfg.Port, cfg.TCP, cfg.Timeout, cfg.Passthrough,
		joinHostPort(cfg.UpstreamHost, cfg.UpstreamPort), proxyResolver, logger)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		return err
	}
	if err := os.WriteFile(startedFlag, nil, 0o644); err != nil {
		server.Shutdown()
		return fmt.Errorf("create %s: %w", startedFlag, err)
	}
	defer func() { _ = os.Remove(startedFlag) }()

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	for sig := range signals {
		switch sig {
		case syscall.SIGHUP:
			newASN, newOrganizations, reloadErr := matcher.Reload()
			if reloadErr != nil {
				logger.Error("failed to reload ASN list, keeping previous list", "error", reloadErr)
			} else {
				logger.Info("reloaded ASN rules", "asn_numbers", newASN, "organization_rules", newOrganizations)
			}
		case syscall.SIGINT, syscall.SIGTERM:
			cancel()
			server.Shutdown()
			return nil
		}
	}
	server.Shutdown()
	return nil
}

func newLogger(prefix bool) *slog.Logger {
	options := &slog.HandlerOptions{Level: slog.LevelInfo}
	if !prefix {
		options.ReplaceAttr = func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return attr
		}
	}
	return slog.New(slog.NewTextHandler(os.Stderr, options))
}

func displayAddress(address string) string {
	if address == "" {
		return "*"
	}
	return address
}

func transport(tcp bool) string {
	if tcp {
		return "UDP/TCP"
	}
	return "UDP"
}

func joinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}
