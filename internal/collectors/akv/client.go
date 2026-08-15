// Package akv implements a read-only Azure Key Vault Certificates client that
// feeds cloud.Collect with source cloud_akv. No key-export APIs.
package akv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors"
	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/collectors/cloud"
)

const ScanSource = "cloud_akv"
const apiVersion = "7.4"

// VaultSource is a PublicCertSource backed by Key Vault REST (list + get public cer).
type VaultSource struct {
	VaultURI string
	Token    string
	HTTP     *http.Client
}

func (s *VaultSource) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (s *VaultSource) base() string {
	return strings.TrimRight(s.VaultURI, "/")
}

// List returns certificate names in the vault.
func (s *VaultSource) List(ctx context.Context) ([]string, error) {
	if s.VaultURI == "" {
		return nil, fmt.Errorf("AZURE_KEY_VAULT_URI required")
	}
	u := fmt.Sprintf("%s/certificates?api-version=%s", s.base(), apiVersion)
	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	if err := s.getJSON(ctx, u, &out); err != nil {
		return nil, err
	}
	var names []string
	for _, v := range out.Value {
		names = append(names, nameFromID(v.ID))
	}
	return names, nil
}

// GetPublicPEM fetches the public certificate (cer → PEM). Never calls key APIs.
func (s *VaultSource) GetPublicPEM(ctx context.Context, name string) (string, error) {
	u := fmt.Sprintf("%s/certificates/%s?api-version=%s", s.base(), url.PathEscape(name), apiVersion)
	var out struct {
		CER string `json:"cer"`
	}
	if err := s.getJSON(ctx, u, &out); err != nil {
		return "", err
	}
	if out.CER == "" {
		return "", nil
	}
	der, err := base64.StdEncoding.DecodeString(out.CER)
	if err != nil {
		der, err = base64.RawURLEncoding.DecodeString(out.CER)
		if err != nil {
			return "", fmt.Errorf("decode cer: %w", err)
		}
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

func (s *VaultSource) getJSON(ctx context.Context, rawURL string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("akv %s: status %d", rawURL, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

func nameFromID(id string) string {
	// .../certificates/{name} or .../certificates/{name}/{version}
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i, p := range parts {
		if p == "certificates" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return id
}

// Collect runs cloud.Collect with source cloud_akv.
func Collect(ctx context.Context, up collectors.Upserter, scanID uuid.UUID, src cloud.PublicCertSource) (ingested, skipped int, err error) {
	return cloud.Collect(ctx, up, scanID, ScanSource, src)
}

// Ensure VaultSource implements cloud.PublicCertSource.
var _ cloud.PublicCertSource = (*VaultSource)(nil)
