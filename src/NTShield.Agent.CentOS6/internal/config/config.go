package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	Agent      AgentConfig      `json:"agent"`
	Central    CentralConfig    `json:"central"`
	Collection CollectionConfig `json:"collection"`
	Paths      PathsConfig      `json:"paths"`
}

type AgentConfig struct {
	ID           string `json:"id"`
	ComputerName string `json:"computer_name"`
}

type CentralConfig struct {
	URL                   string `json:"url"`
	EnrollmentToken       string `json:"enrollment_token"`
	APIKey                string `json:"api_key"`
	CAFile                string `json:"ca_file"`
	ClientCertificateFile string `json:"client_certificate_file"`
	ClientKeyFile         string `json:"client_key_file"`
	InsecureSkipVerify    bool   `json:"insecure_skip_verify"`
	TimeoutSeconds        int    `json:"timeout_seconds"`
}

type CollectionConfig struct {
	LogPollSeconds           int          `json:"log_poll_seconds"`
	ConnectionPollSeconds    int          `json:"connection_poll_seconds"`
	FlushIntervalSeconds     int          `json:"flush_interval_seconds"`
	HeartbeatIntervalSeconds int          `json:"heartbeat_interval_seconds"`
	MaxBatchEvents           int          `json:"max_batch_events"`
	MaxBatchConnections      int          `json:"max_batch_connections"`
	MaxMemoryItems           int          `json:"max_memory_items"`
	MaxSpoolBytes            int64        `json:"max_spool_bytes"`
	MaxLineBytes             int          `json:"max_line_bytes"`
	MaxWAFEventBytes         int          `json:"max_waf_event_bytes"`
	MaxConnections           int          `json:"max_connections"`
	StartAtEnd               bool         `json:"start_at_end"`
	CollectClosedConnections bool         `json:"collect_closed_connections"`
	LogFiles                 []string     `json:"log_files"`
	WAFLogFiles              []string     `json:"waf_log_files"`
	Syslog                   SyslogConfig `json:"syslog"`
}

type SyslogConfig struct {
	Enabled         bool   `json:"enabled"`
	Listen          string `json:"listen"`
	MaxMessageBytes int    `json:"max_message_bytes"`
}

type PathsConfig struct {
	StateDir string `json:"state_dir"`
	SpoolDir string `json:"spool_dir"`
	LogFile  string `json:"log_file"`
}

func Default() Config {
	return Config{
		Central: CentralConfig{
			URL:            "https://127.0.0.1:7443",
			TimeoutSeconds: 20,
		},
		Collection: CollectionConfig{
			LogPollSeconds:           3,
			ConnectionPollSeconds:    30,
			FlushIntervalSeconds:     15,
			HeartbeatIntervalSeconds: 60,
			MaxBatchEvents:           500,
			MaxBatchConnections:      1500,
			MaxMemoryItems:           10000,
			MaxSpoolBytes:            256 * 1024 * 1024,
			MaxLineBytes:             256 * 1024,
			MaxWAFEventBytes:         512 * 1024,
			MaxConnections:           10000,
			StartAtEnd:               true,
			CollectClosedConnections: true,
			LogFiles: []string{
				"/var/log/messages",
				"/var/log/secure",
				"/var/log/audit/audit.log",
			},
			WAFLogFiles: []string{
				"/var/log/modsec_audit.log",
				"/var/log/httpd/modsec_audit.log",
				"/var/log/httpd/modsec_audit.log.*",
				"/var/log/httpd/error_log",
				"/var/log/modsecurity/audit.log",
				"/var/log/nginx/modsec_audit.log",
				"/var/log/nginx/error.log",
			},
			Syslog: SyslogConfig{
				Enabled:         true,
				Listen:          "127.0.0.1:5514",
				MaxMessageBytes: 65507,
			},
		},
		Paths: PathsConfig{
			StateDir: "/var/lib/ntshield-agent",
			SpoolDir: "/var/spool/ntshield-agent",
			LogFile:  "/var/log/ntshield/centos6-agent.log",
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	c.Central.URL = strings.TrimRight(strings.TrimSpace(c.Central.URL), "/")
	if c.Central.URL == "" {
		return errors.New("central.url is required")
	}
	u, err := url.Parse(c.Central.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("central.url must be an absolute http/https URL: %q", c.Central.URL)
	}
	if c.Central.TimeoutSeconds < 5 {
		c.Central.TimeoutSeconds = 20
	}
	if c.Collection.LogPollSeconds < 1 {
		c.Collection.LogPollSeconds = 3
	}
	if c.Collection.ConnectionPollSeconds < 5 {
		c.Collection.ConnectionPollSeconds = 30
	}
	if c.Collection.FlushIntervalSeconds < 2 {
		c.Collection.FlushIntervalSeconds = 15
	}
	if c.Collection.HeartbeatIntervalSeconds < 15 {
		c.Collection.HeartbeatIntervalSeconds = 60
	}
	if c.Collection.MaxBatchEvents < 1 {
		c.Collection.MaxBatchEvents = 500
	}
	if c.Collection.MaxBatchConnections < 1 {
		c.Collection.MaxBatchConnections = 1500
	}
	if c.Collection.MaxMemoryItems < c.Collection.MaxBatchEvents+c.Collection.MaxBatchConnections {
		c.Collection.MaxMemoryItems = 10000
	}
	if c.Collection.MaxSpoolBytes < 1024*1024 {
		c.Collection.MaxSpoolBytes = 256 * 1024 * 1024
	}
	if c.Collection.MaxLineBytes < 4096 {
		c.Collection.MaxLineBytes = 256 * 1024
	}
	if c.Collection.MaxWAFEventBytes < c.Collection.MaxLineBytes {
		c.Collection.MaxWAFEventBytes = 512 * 1024
	}
	if c.Collection.MaxConnections < 100 {
		c.Collection.MaxConnections = 10000
	}
	if c.Collection.Syslog.Listen == "" {
		c.Collection.Syslog.Listen = "127.0.0.1:5514"
	}
	if c.Collection.Syslog.MaxMessageBytes < 1024 || c.Collection.Syslog.MaxMessageBytes > 65507 {
		c.Collection.Syslog.MaxMessageBytes = 65507
	}
	if c.Paths.StateDir == "" || c.Paths.SpoolDir == "" || c.Paths.LogFile == "" {
		return errors.New("paths.state_dir, paths.spool_dir and paths.log_file are required")
	}
	return nil
}

func Write(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
