package governance

import "testing"

func TestClassifyScope(t *testing.T) {
	tests := []struct {
		name        string
		chainStatus string
		issuerDN    string
		hostname    string
		environment string
		want        string
	}{
		{
			name:        "self signed",
			chainStatus: "self_signed",
			issuerDN:    "CN=app",
			want:        ScopeInternal,
		},
		{
			name:     "lets encrypt issuer",
			issuerDN: "CN=R3,O=Let's Encrypt,C=US",
			want:     ScopeExternal,
		},
		{
			name:     "digicert issuer",
			issuerDN: "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc",
			want:     ScopeExternal,
		},
		{
			name:     "internal hostname suffix",
			hostname: "api.corp.internal",
			issuerDN: "CN=Corp Root CA,O=Example Corp",
			want:     ScopeInternal,
		},
		{
			name:     "localhost",
			hostname: "localhost",
			want:     ScopeInternal,
		},
		{
			name:        "dev environment",
			environment: "dev",
			issuerDN:    "CN=Unknown CA",
			want:        ScopeInternal,
		},
		{
			name:     "vault issuer hint",
			issuerDN: "CN=Vault PKI Intermediate,O=HashiCorp Vault",
			want:     ScopeInternal,
		},
		{
			name:     "unknown issuer defaults external",
			issuerDN: "CN=Some Private CA,O=Acme",
			want:     ScopeExternal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyScope(tt.chainStatus, tt.issuerDN, tt.hostname, tt.environment)
			if got != tt.want {
				t.Fatalf("ClassifyScope() = %q, want %q", got, tt.want)
			}
		})
	}
}
