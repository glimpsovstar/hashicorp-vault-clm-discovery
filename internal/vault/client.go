package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpTimeout bounds every Vault request so an unresponsive Vault cannot wedge
// the caller (notably the single post-scan reconcile goroutine).
const httpTimeout = 30 * time.Second

type Config struct {
	Address    string
	Namespace  string
	Token      string
	AuthMethod string
}

type Client struct {
	cfg    Config
	http   *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.Address != "" && !strings.HasPrefix(cfg.Address, "http://") && !strings.HasPrefix(cfg.Address, "https://") {
		cfg.Address = "https://" + cfg.Address
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: httpTimeout},
	}, nil
}

func (c *Client) Configured() bool {
	return c.cfg.Address != ""
}

func (c *Client) ListMounts(ctx context.Context) (map[string]interface{}, error) {
	if !c.Configured() {
		return nil, fmt.Errorf("vault client is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.cfg.Address, "/")+"/v1/sys/mounts", nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if c.cfg.Token != "" {
		req.Header.Set("X-Vault-Token", c.cfg.Token)
	}
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request sys/mounts: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sys/mounts: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	mounts := make(map[string]interface{})
	for k, v := range raw {
		if strings.HasSuffix(k, "/") {
			mounts[k] = v
		}
	}

	return mounts, nil
}
