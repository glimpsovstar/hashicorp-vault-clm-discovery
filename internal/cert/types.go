package cert

import "time"

type ChainStatus string

const (
	ChainComplete      ChainStatus = "complete"
	ChainSelfSigned    ChainStatus = "self_signed"
	ChainIncomplete    ChainStatus = "incomplete"
	ChainUntrustedRoot ChainStatus = "untrusted_root"
)

type ParsedCertificate struct {
	SerialNumber          string
	FingerprintSHA256     string
	SubjectCN             string
	SubjectAltNames       []string
	IssuerDN              string
	AuthorityKeyID        string
	NotBefore             time.Time
	NotAfter              time.Time
	KeyType               string
	KeyBits               int
	SignatureAlgorithm    string
	IsCA                  bool
	KeyUsage              []string
	ExtKeyUsage           []string
	PEM                   string
	CRLDistributionPoints []string
	OCSPServers           []string
	ChainStatus           ChainStatus
	HostnameMatchesSAN    bool
}

type Observation struct {
	IP          string
	Port        int
	Hostname    string
	SNI         string
	TLSVersion  string
	CipherSuite string
	ObservedAt  time.Time
}
