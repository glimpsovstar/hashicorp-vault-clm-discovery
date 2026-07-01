package vault

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
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

func normalizeMount(mount string) string {
	if !strings.HasSuffix(mount, "/") {
		return mount + "/"
	}
	return mount
}

func (c *Client) setVaultHeaders(req *http.Request) {
	if c.cfg.Token != "" {
		req.Header.Set("X-Vault-Token", c.cfg.Token)
	}
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
}
