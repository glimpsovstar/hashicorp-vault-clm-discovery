package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func (c *Client) ListPKIMounts(ctx context.Context) ([]string, error) {
	mounts, err := c.ListMounts(ctx)
	if err != nil {
		return nil, err
	}

	var paths []string
	for path, v := range mounts {
		m, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		t, ok := m["type"].(string)
		if ok && t == "pki" {
			paths = append(paths, path)
		}
	}

	return paths, nil
}

func (c *Client) ListCertSerials(ctx context.Context, mount string) ([]string, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("vault client is not configured")
	}

	mount = normalizeMount(mount)
	url := strings.TrimRight(c.cfg.Address, "/") + "/v1/" + mount + "certs"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	// Vault's PKI cert-list endpoint only supports the LIST operation; a plain
	// GET returns 405. GET with ?list=true is the documented equivalent.
	req.URL.RawQuery = "list=true"
	c.setVaultHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s: %w", mount+"certs", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Vault's LIST convention returns 404 when a mount has no stored certs; that
	// is an empty list, not an error.
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%scerts: status %d: %s", mount, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return raw.Data.Keys, nil
}

func (c *Client) ReadCert(ctx context.Context, mount, serial string) (string, map[string]interface{}, error) {
	if !c.Configured() {
		return "", nil, fmt.Errorf("vault client is not configured")
	}

	mount = normalizeMount(mount)
	url := strings.TrimRight(c.cfg.Address, "/") + "/v1/" + mount + "cert/" + serial

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("create request: %w", err)
	}
	c.setVaultHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("request %scert/%s: %w", mount, serial, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("%scert/%s: status %d: %s", mount, serial, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return "", nil, fmt.Errorf("decode response: %w", err)
	}

	certPEM, ok := raw.Data["certificate"].(string)
	if !ok || certPEM == "" {
		return "", nil, fmt.Errorf("response missing certificate field")
	}

	return certPEM, raw.Data, nil
}

func FingerprintSHA256FromPEM(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("invalid PEM")
	}

	raw, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	fp := sha256.Sum256(raw.Raw)
	return hex.EncodeToString(fp[:]), nil
}

// IssuerImportResult summarizes a pki/issuers/import/bundle write.
type IssuerImportResult struct {
	ImportedIssuers []string          `json:"imported_issuers"`
	ImportedKeys    []string          `json:"imported_keys"`
	Mapping         map[string]string `json:"mapping"`
}

// ImportIssuerBundle imports CA material into a Vault PKI mount via
// pki/issuers/import/bundle. This is the client's first WRITE path and requires
// a read-write PKI policy; a read-only token yields a Vault 403 surfaced here.
func (c *Client) ImportIssuerBundle(ctx context.Context, mount, pemBundle string) (IssuerImportResult, error) {
	if !c.Configured() {
		return IssuerImportResult{}, fmt.Errorf("vault client is not configured")
	}
	mount = normalizeMount(mount)
	url := strings.TrimRight(c.cfg.Address, "/") + "/v1/" + mount + "issuers/import/bundle"

	payload, err := json.Marshal(map[string]string{"pem_bundle": pemBundle})
	if err != nil {
		return IssuerImportResult{}, fmt.Errorf("encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return IssuerImportResult{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setVaultHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return IssuerImportResult{}, fmt.Errorf("request %sissuers/import/bundle: %w", mount, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return IssuerImportResult{}, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return IssuerImportResult{}, fmt.Errorf("%sissuers/import/bundle: status %d: %s", mount, resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Data IssuerImportResult `json:"data"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return IssuerImportResult{}, fmt.Errorf("decode response: %w", err)
	}
	return out.Data, nil
}

func normalizeMount(mount string) string {
	if !strings.HasSuffix(mount, "/") {
		return mount + "/"
	}
	return mount
}

// revocationFromMeta reports whether Vault marks the serial revoked. Vault's
// pki/cert/{serial} response carries revocation_time in unix seconds (0 when
// not revoked). Depending on how the response was decoded the value may arrive
// as a float64 (default json), a json.Number, or a string, so all are handled.
func revocationFromMeta(meta map[string]interface{}) bool {
	v, ok := meta["revocation_time"]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case float64:
		return t > 0
	case int:
		return t > 0
	case int64:
		return t > 0
	case json.Number:
		n, err := t.Int64()
		return err == nil && n > 0
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return err == nil && n > 0
	default:
		return false
	}
}

func (c *Client) setVaultHeaders(req *http.Request) {
	if c.cfg.Token != "" {
		req.Header.Set("X-Vault-Token", c.cfg.Token)
	}
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
}
