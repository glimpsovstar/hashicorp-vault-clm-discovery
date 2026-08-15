package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/glimpsovstar/hashicorp-vault-clm-discovery/internal/config"
)

// resolveAzureToken returns a bearer for Key Vault. Prefers AZURE_ACCESS_TOKEN
// (tests/lab), else client-credentials against the tenant. Never logs secrets.
func resolveAzureToken(ctx context.Context, cfg config.Config) (string, error) {
	if t := strings.TrimSpace(cfg.AzureAccessToken); t != "" {
		return t, nil
	}
	if cfg.AzureTenantID == "" || cfg.AzureClientID == "" || cfg.AzureClientSecret == "" {
		return "", fmt.Errorf("azure client credentials incomplete")
	}
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", cfg.AzureClientID)
	form.Set("client_secret", cfg.AzureClientSecret)
	form.Set("scope", "https://vault.azure.net/.default")
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(cfg.AzureTenantID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("azure token endpoint status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("azure token empty")
	}
	return out.AccessToken, nil
}
