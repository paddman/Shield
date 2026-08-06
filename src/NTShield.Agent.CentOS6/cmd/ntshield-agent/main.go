package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/agent"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/config"
)

var version = "0.1.0"

func main() {
	var (
		configPath      = flag.String("config", "/etc/ntshield-agent/config.json", "configuration file")
		once            = flag.Bool("once", false, "collect/send once, then exit")
		checkConfig     = flag.Bool("check-config", false, "validate configuration, then exit")
		showVersion     = flag.Bool("version", false, "print version, then exit")
		writeConfig     = flag.String("write-config", "", "write a new default configuration to this path")
		centralURL      = flag.String("central-url", "", "Central URL used with -write-config")
		enrollmentToken = flag.String("enrollment-token", "", "enrollment token used with -write-config")
		apiKey          = flag.String("api-key", "", "existing agent API key used with -write-config")
		caFile          = flag.String("ca-file", "", "CA certificate file used with -write-config")
		insecure        = flag.Bool("insecure", false, "disable TLS verification in generated config")
		syslogListen    = flag.String("syslog-listen", "", "UDP bind address used with -write-config")
		disableSyslog   = flag.Bool("disable-syslog", false, "disable UDP syslog listener in generated config")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("NT Shield CentOS 6 Agent %s\n", version)
		return
	}
	if *writeConfig != "" {
		cfg := config.Default()
		if *centralURL != "" {
			cfg.Central.URL = *centralURL
		}
		token := *enrollmentToken
		if token == "" {
			token = os.Getenv("NTSHIELD_BOOTSTRAP_ENROLLMENT_TOKEN")
		}
		key := *apiKey
		if key == "" {
			key = os.Getenv("NTSHIELD_BOOTSTRAP_API_KEY")
		}
		cfg.Central.EnrollmentToken = token
		cfg.Central.APIKey = key
		cfg.Central.CAFile = *caFile
		cfg.Central.InsecureSkipVerify = *insecure
		cfg.Collection.Syslog.Enabled = !*disableSyslog
		if *syslogListen != "" {
			cfg.Collection.Syslog.Listen = *syslogListen
		}
		if err := config.Write(*writeConfig, cfg); err != nil {
			fatalf("write config: %v", err)
		}
		fmt.Printf("wrote %s\n", *writeConfig)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fatalf("configuration error: %v", err)
	}
	if *checkConfig {
		fmt.Printf("configuration OK: central=%s syslog=%v/%s\n", cfg.Central.URL, cfg.Collection.Syslog.Enabled, cfg.Collection.Syslog.Listen)
		return
	}

	logger, closer, err := newLogger(cfg.Paths.LogFile)
	if err != nil {
		fatalf("logger: %v", err)
	}
	defer closer.Close()

	exe, _ := os.Executable()
	runner, err := agent.New(cfg, version, exe, logger)
	if err != nil {
		logger.Fatalf("initialize agent: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if *once {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
	}
	if err := runner.Run(ctx, *once); err != nil {
		logger.Fatalf("agent stopped with error: %v", err)
	}
}

func newLogger(path string) (*log.Logger, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	writer := io.MultiWriter(os.Stdout, f)
	return log.New(writer, "ntshield-centos6 ", log.LstdFlags|log.LUTC|log.Lmicroseconds), f, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
