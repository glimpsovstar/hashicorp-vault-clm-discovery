package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/cert"
)

type Target struct {
	IP       string
	Port     int
	Hostname string // DNS name for SNI (empty for CIDR-only targets)
}

type ProbeResult struct {
	Target      Target
	Certificate cert.ParsedCertificate
	Chain       []cert.ParsedCertificate
	Observation cert.Observation
	Error       error
}

type Config struct {
	Timeout            time.Duration
	AllowPrivateRanges bool
}

type Scanner struct {
	cfg Config
}

func New(cfg Config) *Scanner {
	return &Scanner{cfg: cfg}
}

func ExpandTargets(cidrs []string, ports []int, allowPrivate bool) ([]Target, error) {
	var targets []Target
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q: %w", cidr, err)
		}
		if !allowPrivate && isPrivatePrefix(prefix) {
			return nil, fmt.Errorf("private range %q blocked; set ALLOW_PRIVATE_RANGES=true", cidr)
		}
		if prefix.Addr().Is4() && prefix.Bits() < 16 {
			return nil, fmt.Errorf("cidr %q too large; maximum /16 for IPv4", cidr)
		}

		for addr := prefix.Masked().Addr(); prefix.Contains(addr); addr = addr.Next() {
			for _, port := range ports {
				targets = append(targets, Target{IP: addr.String(), Port: port})
			}
		}
	}
	return targets, nil
}

func ExpandHostnames(hostnames []string, ports []int) ([]Target, error) {
	targets, _, err := ExpandHostnamesPartial(hostnames, ports)
	return targets, err
}

// ExpandHostnamesPartial resolves hostnames to scan targets. Unresolvable names
// are skipped and returned as warnings so other hostnames can still be scanned.
func ExpandHostnamesPartial(hostnames []string, ports []int) ([]Target, []string, error) {
	var targets []Target
	var warnings []string
	for _, host := range hostnames {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		ips, err := net.LookupIP(host)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skipped %q: %v", host, err))
			continue
		}
		if len(ips) == 0 {
			warnings = append(warnings, fmt.Sprintf("skipped %q: no addresses", host))
			continue
		}
		added := false
		for _, ip := range ips {
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			added = true
			for _, port := range ports {
				targets = append(targets, Target{IP: ip4.String(), Port: port, Hostname: host})
			}
		}
		if !added {
			warnings = append(warnings, fmt.Sprintf("skipped %q: no IPv4 addresses", host))
		}
	}
	if len(targets) == 0 {
		if len(warnings) > 0 {
			return nil, warnings, fmt.Errorf("no resolvable hostnames (%s)", strings.Join(warnings, "; "))
		}
		return nil, warnings, fmt.Errorf("no targets from hostnames")
	}
	return targets, warnings, nil
}

func ExpandScanTargets(cidrs, hostnames []string, ports []int, allowPrivate bool) ([]Target, []string, error) {
	var targets []Target
	var warnings []string
	if len(cidrs) > 0 {
		fromCIDR, err := ExpandTargets(cidrs, ports, allowPrivate)
		if err != nil {
			return nil, warnings, err
		}
		targets = append(targets, fromCIDR...)
	}
	if len(hostnames) > 0 {
		fromHost, hostWarnings, err := ExpandHostnamesPartial(hostnames, ports)
		warnings = append(warnings, hostWarnings...)
		if err != nil {
			return nil, warnings, err
		}
		targets = append(targets, fromHost...)
	}
	if len(targets) == 0 {
		return nil, warnings, fmt.Errorf("no scan targets: provide cidrs and/or hostnames")
	}
	return targets, warnings, nil
}

func isPrivatePrefix(p netip.Prefix) bool {
	addr := p.Addr()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
}

func (s *Scanner) Probe(ctx context.Context, target Target) ProbeResult {
	result := ProbeResult{Target: target}
	addr := net.JoinHostPort(target.IP, fmt.Sprintf("%d", target.Port))

	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	sni := target.Hostname
	if sni == "" {
		sni = target.IP
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sni,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		result.Error = err
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		result.Error = fmt.Errorf("no peer certificates")
		return result
	}

	hostname := target.Hostname
	if hostname == "" {
		hostname = target.IP
		if names, err := net.LookupAddr(target.IP); err == nil && len(names) > 0 {
			hostname = strings.TrimSuffix(names[0], ".")
		}
	}

	leaf := state.PeerCertificates[0]
	parsed := cert.ParseCertificate(leaf, state.PeerCertificates, hostname, sni)

	var chain []cert.ParsedCertificate
	for _, c := range state.PeerCertificates[1:] {
		chain = append(chain, cert.ParseCertificate(c, state.PeerCertificates, hostname, sni))
	}

	result.Certificate = parsed
	result.Chain = chain
	result.Observation = cert.Observation{
		IP:          target.IP,
		Port:        target.Port,
		Hostname:    hostname,
		SNI:         sni,
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ObservedAt:  time.Now().UTC(),
	}
	return result
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}

// ParsePEMChain parses a PEM-encoded certificate chain for testing.
func ParsePEMChain(rawCerts []*x509.Certificate) []cert.ParsedCertificate {
	var out []cert.ParsedCertificate
	for i, c := range rawCerts {
		chain := rawCerts[i:]
		out = append(out, cert.ParseCertificate(c, chain, "", ""))
	}
	return out
}
