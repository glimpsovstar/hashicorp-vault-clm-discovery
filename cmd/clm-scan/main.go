package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
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

	if !*consent {
		log.Fatal("scanning requires --i-consent-to-scan flag confirming authorized use")
	}
	if *cidrs == "" && *hostnames == "" {
		log.Fatal("--cidrs and/or --hostnames required")
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	cidrList := splitCSV(*cidrs)
	hostnameList := splitCSV(*hostnames)
	portList, err := parsePorts(*ports)
	if err != nil {
		log.Fatal(err)
	}

	st := store.New(pool, cfg.ExpiringSoonDays)
	sc := scanner.New(scanner.Config{
		Timeout:            cfg.ScanTimeout,
		AllowPrivateRanges: cfg.AllowPrivateRanges,
	})

	scan, err := st.CreateScan(ctx, cidrList, hostnameList, portList, *concurrency)
	if err != nil {
		log.Fatal(err)
	}

	targets, warnings, err := scanner.ExpandScanTargets(cidrList, hostnameList, portList, cfg.AllowPrivateRanges)
	if err != nil {
		_ = st.FailScan(ctx, scan.ID, err.Error())
		log.Fatal(err)
	}
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	if err := st.UpdateScanRunning(ctx, scan.ID, len(targets)); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("scan %s: probing %d targets\n", scan.ID, len(targets))

	var wg sync.WaitGroup
	sem := make(chan struct{}, *concurrency)
	var mu sync.Mutex
	scanned, certsFound := 0, 0

	for _, target := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t scanner.Target) {
			defer wg.Done()
			defer func() { <-sem }()

			result := sc.Probe(ctx, t)
			mu.Lock()
			scanned++
			if result.Error == nil {
				if _, err := st.UpsertCertificate(ctx, scan.ID, result.Certificate, result.Observation); err != nil {
					log.Printf("upsert error: %v", err)
				} else {
					certsFound++
				}
			}
			curScanned, curCerts := scanned, certsFound
			mu.Unlock()

			if curScanned%50 == 0 {
				fmt.Printf("progress: %d/%d, certs=%d\n", curScanned, len(targets), curCerts)
				_ = st.UpdateScanProgress(ctx, scan.ID, curScanned, curCerts)
			}
		}(target)
	}

	wg.Wait()
	var warnMsg *string
	if len(warnings) > 0 {
		msg := strings.Join(warnings, "; ")
		warnMsg = &msg
	}
	_ = st.CompleteScan(ctx, scan.ID, scanned, certsFound, warnMsg)
	fmt.Printf("scan complete: %d targets, %d certificates found\n", scanned, certsFound)
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		ports = append(ports, n)
	}
	return ports, nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
