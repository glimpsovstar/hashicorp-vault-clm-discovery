//go:build integration

// Package integration drives the CA-import (mode B) flow against a real Vault
// and a self-signed endpoint provisioned by Terraform (test/integration/terraform/local).
// It is build-tagged and excluded from the default `go test ./...`; the harness
// script test/integration/run-integration.sh stands up the stack, exports the
// env below, runs this test, then tears the stack down.
package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"
)

type env struct {
	appURL     string
	vaultAddr  string
	vaultToken string
	pkiMount   string
	caCN       string
	scanTarget string
}

func loadEnv(t *testing.T) env {
	t.Helper()
	e := env{
		appURL:     os.Getenv("INTEGRATION_APP_URL"),
		vaultAddr:  os.Getenv("INTEGRATION_VAULT_ADDR"),
		vaultToken: os.Getenv("INTEGRATION_VAULT_TOKEN"),
		pkiMount:   os.Getenv("INTEGRATION_PKI_MOUNT"),
		caCN:       os.Getenv("INTEGRATION_CA_CN"),
		scanTarget: os.Getenv("INTEGRATION_SCAN_TARGET"),
	}
	if e.appURL == "" || e.vaultAddr == "" {
		t.Skip("integration env not set (run via test/integration/run-integration.sh)")
	}
	if e.pkiMount == "" {
		e.pkiMount = "pki"
	}
	return e
}

func TestIntegration_CAImportToVault(t *testing.T) {
	e := loadEnv(t)
	c := &http.Client{Timeout: 15 * time.Second}

	// 1. Scan the self-signed endpoint (in-network DNS name, port 443).
	scanID := postJSON(t, c, e.appURL+"/api/v1/scans", map[string]any{
		"hostnames": []string{e.scanTarget},
		"ports":     []int{443},
		"consent":   true,
	})["id"].(string)
	if scanID == "" {
		t.Fatal("scan did not return an id")
	}

	// 2. Wait for completion.
	waitScanComplete(t, c, e.appURL, scanID)

	// 3. Find the discovered CA issuer.
	issuerID := findCAIssuer(t, c, e.appURL, e.caCN)
	if issuerID == "" {
		t.Fatalf("CA issuer %q not discovered from the scanned chain", e.caCN)
	}

	// 4. Import the CA into Vault (mode B).
	imp := postJSON(t, c, e.appURL+"/api/v1/issuers/"+issuerID+"/import", map[string]any{
		"consent": true,
		"mount":   e.pkiMount,
	})
	if imp["vault_pki_mount"] == nil || imp["vault_pki_mount"] == "" {
		t.Fatalf("import response missing vault_pki_mount: %v", imp)
	}

	// 5. Verify the CA is now readable in Vault's PKI mount.
	if !vaultHasIssuers(t, c, e) {
		t.Fatalf("Vault mount %q has no issuers after import", e.pkiMount)
	}
}

func postJSON(t *testing.T, c *http.Client, url string, body map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s: status %d: %s", url, resp.StatusCode, out)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("POST %s: decode: %v (%s)", url, err, out)
	}
	return m
}

func waitScanComplete(t *testing.T, c *http.Client, appURL, id string) {
	t.Helper()
	for i := 0; i < 60; i++ {
		resp, err := c.Get(appURL + "/api/v1/scans/" + id)
		if err == nil {
			out, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			var m map[string]any
			if json.Unmarshal(out, &m) == nil {
				switch m["status"] {
				case "completed":
					return
				case "failed":
					t.Fatalf("scan %s failed: %v", id, m["error"])
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("scan %s did not complete in time", id)
}

func findCAIssuer(t *testing.T, c *http.Client, appURL, caCN string) string {
	t.Helper()
	resp, err := c.Get(appURL + "/api/v1/issuers")
	if err != nil {
		t.Fatalf("GET /issuers: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	var body struct {
		Items []struct {
			ID        string `json:"id"`
			SubjectCN string `json:"subject_cn"`
			IsCA      bool   `json:"is_ca"`
		} `json:"items"`
	}
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatalf("decode issuers: %v (%s)", err, out)
	}
	for _, it := range body.Items {
		if it.IsCA && it.SubjectCN == caCN {
			return it.ID
		}
	}
	// Fall back to any CA issuer if the CN differs.
	for _, it := range body.Items {
		if it.IsCA {
			return it.ID
		}
	}
	return ""
}

func vaultHasIssuers(t *testing.T, c *http.Client, e env) bool {
	t.Helper()
	url := fmt.Sprintf("%s/v1/%s/issuers?list=true", e.vaultAddr, e.pkiMount)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Vault-Token", e.vaultToken)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("vault list issuers: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	out, _ := io.ReadAll(resp.Body)
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(out, &body); err != nil {
		return false
	}
	return len(body.Data.Keys) > 0
}
