package agent

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/collector"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/config"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/parser"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/spool"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/transport"
)

type Agent struct {
	cfg          config.Config
	version      string
	logger       *log.Logger
	agentID      string
	computerName string
	osVersion    string
	hostIP       string
	binarySHA256 string

	tailer    *collector.Tailer
	waf       *parser.WAFAccumulator
	procNet   *collector.ProcNetCollector
	metrics   *collector.MetricsCollector
	spool     *spool.Store
	transport *transport.Client

	bufMu       sync.Mutex
	events      []model.SecurityEventRecord
	connections []model.NetworkConnectionRecord
	alerts      []model.DetectionAlert
	dropped     int64

	stateMu     sync.RWMutex
	lastError   string
	lastMetrics collector.Metrics
}

func New(cfg config.Config, version, executablePath string, logger *log.Logger) (*Agent, error) {
	for _, dir := range []string{cfg.Paths.StateDir, cfg.Paths.SpoolDir, filepath.Dir(cfg.Paths.LogFile)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	agentID, err := resolveAgentID(cfg.Agent.ID, cfg.Paths.StateDir)
	if err != nil {
		return nil, err
	}
	computerName := strings.TrimSpace(cfg.Agent.ComputerName)
	if computerName == "" {
		computerName, _ = os.Hostname()
	}
	if computerName == "" {
		computerName = "centos6-host"
	}

	tailer, err := collector.NewTailer(filepath.Join(cfg.Paths.StateDir, "tail-offsets.json"), cfg.Collection.StartAtEnd, cfg.Collection.MaxLineBytes)
	if err != nil {
		return nil, err
	}
	spoolStore, err := spool.New(cfg.Paths.SpoolDir, cfg.Collection.MaxSpoolBytes)
	if err != nil {
		return nil, err
	}
	client, err := transport.New(cfg.Central, filepath.Join(cfg.Paths.StateDir, "agent-api-key"), "NTShield-Agent-CentOS6/"+version)
	if err != nil {
		return nil, err
	}

	return &Agent{
		cfg:          cfg,
		version:      version,
		logger:       logger,
		agentID:      agentID,
		computerName: computerName,
		osVersion:    detectOSVersion(),
		hostIP:       primaryHostIP(),
		binarySHA256: sha256File(executablePath),
		tailer:       tailer,
		waf:          parser.NewWAFAccumulator(cfg.Collection.MaxWAFEventBytes),
		procNet:      collector.NewProcNetCollector(cfg.Collection.MaxConnections, cfg.Collection.CollectClosedConnections),
		metrics:      &collector.MetricsCollector{},
		spool:        spoolStore,
		transport:    client,
		events:       make([]model.SecurityEventRecord, 0, cfg.Collection.MaxBatchEvents),
		connections:  make([]model.NetworkConnectionRecord, 0, cfg.Collection.MaxBatchConnections),
		alerts:       make([]model.DetectionAlert, 0, cfg.Collection.MaxBatchEvents/4+1),
	}, nil
}
