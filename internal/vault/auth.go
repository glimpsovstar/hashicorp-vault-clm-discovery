package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// renewSkew is how soon before lease expiry EnsureToken renews a renewable
// AppRole client token.
const renewSkew = 30 * time.Second

type vaultAuthReply struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// usesAppRole reports whether this client authenticates via AppRole.
func (c *Client) usesAppRole() bool {
	return strings.EqualFold(strings.TrimSpace(c.cfg.AuthMethod), "approle")
}

// Login performs an AppRole login and caches the client token. For token auth
// it is a no-op. Login always fetches a fresh token; use EnsureToken to reuse
// a still-valid cached token.
func (c *Client) Login(ctx context.Context) error {
	if !c.usesAppRole() {
		return nil
	}
	if !c.Configured() {
		return fmt.Errorf("vault client is not configured")
	}
	if c.cfg.RoleID == "" || c.cfg.SecretID == "" {
		return fmt.Errorf("approle auth requires role_id and secret_id")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginLocked(ctx)
}

// EnsureToken guarantees a usable Vault token is available. Token auth is a
// no-op (callers keep sending Config.Token). AppRole logs in on first use and
// renews before expiry when Vault returned a renewable lease/ttl.
func (c *Client) EnsureToken(ctx context.Context) error {
	if !c.usesAppRole() {
		return nil
	}
	if !c.Configured() {
		return fmt.Errorf("vault client is not configured")
	}
	if c.cfg.RoleID == "" || c.cfg.SecretID == "" {
		return fmt.Errorf("approle auth requires role_id and secret_id")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clientToken == "" {
		return c.loginLocked(ctx)
	}
	if c.expiry.IsZero() || time.Until(c.expiry) > renewSkew {
		return nil
	}
	if c.renewable {
		if err := c.renewLocked(ctx); err == nil {
			return nil
		}
	}
	return c.loginLocked(ctx)
}

func (c *Client) loginLocked(ctx context.Context) error {
	payload, err := json.Marshal(map[string]string{
		"role_id":   c.cfg.RoleID,
		"secret_id": c.cfg.SecretID,
	})
	if err != nil {
		return fmt.Errorf("encode approle login: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL("/v1/auth/approle/login"), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create approle login: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.setNamespaceHeader(req)

	body, status, err := c.doVault(req)
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("approle login: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	return c.applyAuth(body, true)
}

func (c *Client) renewLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL("/v1/auth/token/renew-self"), nil)
	if err != nil {
		return fmt.Errorf("create token renew: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.clientToken)
	c.setNamespaceHeader(req)

	body, status, err := c.doVault(req)
	if err != nil {
		return fmt.Errorf("token renew: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("token renew: status %d: %s", status, strings.TrimSpace(string(body)))
	}
	return c.applyAuth(body, false)
}

func (c *Client) applyAuth(body []byte, tokenRequired bool) error {
	var reply vaultAuthReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return fmt.Errorf("decode vault auth: %w", err)
	}
	if reply.Auth == nil {
		return fmt.Errorf("vault auth response missing auth")
	}
	token := reply.Auth.ClientToken
	if token == "" {
		if tokenRequired {
			return fmt.Errorf("vault auth response missing client_token")
		}
		token = c.clientToken
	}
	c.clientToken = token
	c.renewable = reply.Auth.Renewable
	if reply.Auth.LeaseDuration > 0 {
		c.expiry = time.Now().Add(time.Duration(reply.Auth.LeaseDuration) * time.Second)
	} else {
		c.expiry = time.Time{}
	}
	return nil
}

func (c *Client) apiURL(path string) string {
	return strings.TrimRight(c.cfg.Address, "/") + path
}

func (c *Client) doVault(req *http.Request) ([]byte, int, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

func (c *Client) currentToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.clientToken != "" {
		return c.clientToken
	}
	return c.cfg.Token
}

func (c *Client) setNamespaceHeader(req *http.Request) {
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
}
