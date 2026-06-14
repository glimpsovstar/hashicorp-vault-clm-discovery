package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
)

func ParseCertificate(raw *x509.Certificate, chain []*x509.Certificate, hostname, sni string) ParsedCertificate {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw.Raw})
	fp := sha256.Sum256(raw.Raw)

	sans := collectSANs(raw)
	chainStatus := analyzeChain(raw, chain)
	keyType, keyBits := publicKeyMeta(raw)

	return ParsedCertificate{
		SerialNumber:          raw.SerialNumber.Text(16),
		FingerprintSHA256:     hex.EncodeToString(fp[:]),
		SubjectCN:             raw.Subject.CommonName,
		SubjectAltNames:       sans,
		IssuerDN:              raw.Issuer.String(),
		AuthorityKeyID:        hex.EncodeToString(raw.AuthorityKeyId),
		NotBefore:             raw.NotBefore.UTC(),
		NotAfter:              raw.NotAfter.UTC(),
		KeyType:               keyType,
		KeyBits:               keyBits,
		SignatureAlgorithm:    raw.SignatureAlgorithm.String(),
		IsCA:                  raw.IsCA,
		KeyUsage:              keyUsageStrings(raw),
		ExtKeyUsage:           extKeyUsageStrings(raw),
		PEM:                   string(pemBytes),
		CRLDistributionPoints: raw.CRLDistributionPoints,
		OCSPServers:           raw.OCSPServer,
		ChainStatus:           chainStatus,
		HostnameMatchesSAN:    hostnameMatchesSAN(raw, hostname, sni),
	}
}

func collectSANs(c *x509.Certificate) []string {
	var sans []string
	for _, d := range c.DNSNames {
		sans = append(sans, d)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, e := range c.EmailAddresses {
		sans = append(sans, e)
	}
	return sans
}

func keyUsageStrings(c *x509.Certificate) []string {
	var out []string
	usageMap := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "digital_signature",
		x509.KeyUsageContentCommitment: "content_commitment",
		x509.KeyUsageKeyEncipherment:   "key_encipherment",
		x509.KeyUsageDataEncipherment:  "data_encipherment",
		x509.KeyUsageKeyAgreement:      "key_agreement",
		x509.KeyUsageCertSign:          "cert_sign",
		x509.KeyUsageCRLSign:           "crl_sign",
		x509.KeyUsageEncipherOnly:      "encipher_only",
		x509.KeyUsageDecipherOnly:      "decipher_only",
	}
	for u, name := range usageMap {
		if c.KeyUsage&u != 0 {
			out = append(out, name)
		}
	}
	return out
}

func extKeyUsageStrings(c *x509.Certificate) []string {
	ekuMap := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                        "any",
		x509.ExtKeyUsageServerAuth:                 "server_auth",
		x509.ExtKeyUsageClientAuth:                 "client_auth",
		x509.ExtKeyUsageCodeSigning:                "code_signing",
		x509.ExtKeyUsageEmailProtection:            "email_protection",
		x509.ExtKeyUsageIPSECEndSystem:             "ipsec_end_system",
		x509.ExtKeyUsageIPSECTunnel:                "ipsec_tunnel",
		x509.ExtKeyUsageIPSECUser:                  "ipsec_user",
		x509.ExtKeyUsageTimeStamping:               "time_stamping",
		x509.ExtKeyUsageOCSPSigning:                "ocsp_signing",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto: "microsoft_server_gated_crypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscape_server_gated_crypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "microsoft_commercial_code_signing",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning: "microsoft_kernel_code_signing",
	}
	var out []string
	for _, u := range c.ExtKeyUsage {
		if name, ok := ekuMap[u]; ok {
			out = append(out, name)
		} else {
			out = append(out, fmt.Sprintf("unknown(%d)", u))
		}
	}
	return out
}

func analyzeChain(leaf *x509.Certificate, chain []*x509.Certificate) ChainStatus {
	if leaf.Subject.String() == leaf.Issuer.String() {
		return ChainSelfSigned
	}

	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}

	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	if _, err := leaf.Verify(opts); err == nil {
		return ChainComplete
	}

	if len(chain) <= 1 {
		return ChainIncomplete
	}

	// Chain present but root not trusted
	if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: intermediates}); err == nil {
		return ChainUntrustedRoot
	}

	return ChainIncomplete
}

func hostnameMatchesSAN(c *x509.Certificate, hostname, sni string) bool {
	check := strings.TrimSpace(sni)
	if check == "" {
		check = strings.TrimSpace(hostname)
	}
	if check == "" {
		return true
	}

	if net.ParseIP(check) != nil {
		for _, ip := range c.IPAddresses {
			if ip.String() == check {
				return true
			}
		}
		return len(c.IPAddresses) == 0
	}

	check = strings.ToLower(check)
	for _, d := range c.DNSNames {
		if matchHostname(check, strings.ToLower(d)) {
			return true
		}
	}
	if strings.EqualFold(c.Subject.CommonName, check) {
		return true
	}
	return len(c.DNSNames) == 0 && c.Subject.CommonName == ""
}

func matchHostname(host, pattern string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) && strings.Count(host, ".") >= strings.Count(pattern, ".") {
			return true
		}
	}
	return false
}
