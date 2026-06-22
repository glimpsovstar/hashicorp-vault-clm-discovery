package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cli"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/logging"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanrunner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/scanner"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/store"
)

func main() {
	cidrs := flag.String("cidrs", "", "comma-separated CIDR ranges")
	hostnames := flag.String("hostnames", "", "comma-separated hostnames (uses correct TLS SNI)")
	ports := flag.String("ports", "443,8443,6443,993,465", "comma-separated ports")
	concurrency := flag.Int("concurrency", 50, "scan concurrency")
	consent := flag.Bool("i-consent-to-scan", false, "confirm authorized scanning")
	flag.Parse()

	logger := logging.New(os.Getenv("LOG_LEVEL"))

	if !*consent {
		logger.Error("scanning requires consent", "hint", "pass --i-consent-to-scan")
		os.Exit(1)
	}
	if *cidrs == "" && *hostnames == "" {
		logger.Error("no targets", "hint", "pass --cidrs and/or --hostnames")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}
	logger = logging.New(cfg.LogLevel)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("connect database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	cidrList := cli.SplitCSV(*cidrs)
	hostnameList := cli.SplitCSV(*hostnames)
	portList, err := cli.ParsePorts(*ports)
	if err != nil {
		logger.Error("parse ports", "err", err)
		os.Exit(1)
	}

	st := store.New(pool, cfg.ExpiringSoonDays)
	sc := scanner.New(scanner.Config{
		Timeout:            cfg.ScanTimeout,
		AllowPrivateRanges: cfg.AllowPrivateRanges,
	})

	scan, err := st.CreateScan(ctx, cidrList, hostnameList, portList, *concurrency)
	if err != nil {
		logger.Error("create scan", "err", err)
		os.Exit(1)
	}

	fmt.Printf("scan %s: starting\n", scan.ID)

	runner := scanrunner.New(st, sc, logger, cfg.LogLevel, cfg.AllowPrivateRanges)
	if err := runner.Run(ctx, scanrunner.Job{
		ScanID:      scan.ID,
		CIDRs:       cidrList,
		Hostnames:   hostnameList,
		Ports:       portList,
		Concurrency: *concurrency,
	}); err != nil {
		os.Exit(1)
	}

	completed, err := st.GetScan(ctx, scan.ID)
	if err != nil {
		logger.Error("load scan summary", "err", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"scan complete: %d targets, %d succeeded, %d failed, %d certificates, %d upsert failures, %d warnings\n",
		completed.TargetsTotal,
		completed.TargetsSucceeded,
		completed.TargetsFailed,
		completed.CertsFound,
		completed.UpsertFailures,
		len(completed.ExpansionWarnings),
	)
}
