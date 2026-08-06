package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/config"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
)

const maxResponseBytes = 1024 * 1024

type Client struct {
	mu          sync.RWMutex
	baseURL     string
	apiKey      string
	apiKeyPath  string
	enrollToken string
	http        *http.Client
	userAgent   string
}

func New(cfg config.CentralConfig, apiKeyPath, userAgent string) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.URL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid Central URL %q", cfg.URL)
	}
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, // #nosec G402: explicit legacy-lab option, false by default.
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("CA file contains no readable certificates")
		}
		tlsConfig.RootCAs = roots
	}
	if cfg.ClientCertificateFile != "" || cfg.ClientKeyFile != "" {
		if cfg.ClientCertificateFile == "" || cfg.ClientKeyFile == "" {
			return nil, errors.New("both client_certificate_file and client_key_file are required for mTLS")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertificateFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     60 * time.Second,
		MaxIdleConns:        10,
	}
	client := &Client{
		baseURL:     strings.TrimRight(cfg.URL, "/"),
		apiKey:      strings.TrimSpace(cfg.APIKey),
		apiKeyPath:  apiKeyPath,
		enrollToken: cfg.EnrollmentToken,
		http: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		},
		userAgent: userAgent,
	}
	if data, err := os.ReadFile(apiKeyPath); err == nil && strings.TrimSpace(string(data)) != "" {
		client.apiKey = strings.TrimSpace(string(data))
	}
	return client, nil
}

func (c *Client) Register(ctx context.Context, request model.AgentRegistrationRequest) (model.AgentRegistrationResponse, error) {
	c.mu.RLock()
	hasKey := c.apiKey != ""
	c.mu.RUnlock()
	request.EnrollmentToken = c.enrollToken
	request.RotateAPIKey = !hasKey

	var response model.AgentRegistrationResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/register", request, &response, ""); err != nil {
		return response, err
	}
	if !response.Accepted {
		return response, fmt.Errorf("registration rejected: %s", response.Message)
	}
	if response.AgentAPIKey != "" {
		if err := c.SetAPIKey(response.AgentAPIKey); err != nil {
			return response, fmt.Errorf("store API key: %w", err)
		}
	}
	return response, nil
}

func (c *Client) SendBatch(ctx context.Context, payload []byte, idempotencyKey string) (model.IngestResponse, error) {
	var response model.IngestResponse
	if err := c.doRawJSON(ctx, http.MethodPost, "/api/v1/ingest", payload, &response, idempotencyKey); err != nil {
		return response, err
	}
	if !response.Accepted {
		return response, fmt.Errorf("ingest rejected: %s", response.Message)
	}
	return response, nil
}

func (c *Client) SendHeartbeat(ctx context.Context, heartbeat model.AgentHeartbeat) (model.HeartbeatResponse, error) {
	var response model.HeartbeatResponse
	if err := c.doJSON(ctx, http.MethodPost, "/api/v1/agents/heartbeat", heartbeat, &response, ""); err != nil {
		return response, err
	}
	if !response.Accepted {
		return response, errors.New("heartbeat rejected")
	}
	return response, nil
}

func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/health", nil)
	if err != nil {
		return err
	}
	c.applyHeaders(req, "")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Central health HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) SetAPIKey(apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return errors.New("empty API key")
	}
	if err := os.MkdirAll(filepath.Dir(c.apiKeyPath), 0700); err != nil {
		return err
	}
	tmp := c.apiKeyPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(apiKey+"\n"), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, c.apiKeyPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	c.mu.Lock()
	c.apiKey = apiKey
	c.mu.Unlock()
	return nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, requestBody any, responseBody any, idempotencyKey string) error {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	return c.doRawJSON(ctx, method, path, payload, responseBody, idempotencyKey)
}

func (c *Client) doRawJSON(ctx context.Context, method, path string, payload []byte, responseBody any, idempotencyKey string) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	c.applyHeaders(req, idempotencyKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Central HTTP %d: %s", resp.StatusCode, truncate(strings.TrimSpace(string(body)), 512))
	}
	if responseBody != nil && len(body) > 0 {
		if err := json.Unmarshal(body, responseBody); err != nil {
			return fmt.Errorf("decode Central response: %w", err)
		}
	}
	return nil
}

func (c *Client) applyHeaders(req *http.Request, idempotencyKey string) {
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	c.mu.RLock()
	apiKey := c.apiKey
	c.mu.RUnlock()
	if apiKey != "" {
		req.Header.Set("X-NTShield-Api-Key", apiKey)
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
