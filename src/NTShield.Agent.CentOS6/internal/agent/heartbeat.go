package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/collector"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
)

func (a *Agent) sendHeartbeat(ctx context.Context) {
	depth, spoolBytes, _ := a.spool.Stats()
	a.bufMu.Lock()
	memoryDepth := int64(len(a.events) + len(a.connections) + len(a.alerts))
	dropped := a.dropped
	a.bufMu.Unlock()
	metrics := a.lastMetrics
	summary := collector.FormatMetrics(metrics)
	status := fmt.Sprintf("Healthy | %s | queue=%d dropped=%d", summary, depth+memoryDepth, dropped)
	if a.getLastError() != "" {
		status = fmt.Sprintf("Degraded | %s | queue=%d dropped=%d", summary, depth+memoryDepth, dropped)
	}
	if len(status) > 240 {
		status = status[:240]
	}
	hb := model.AgentHeartbeat{
		AgentID:                 a.agentID,
		ComputerName:            a.computerName,
		AgentVersion:            a.version + "-centos6",
		OSVersion:               a.osVersion,
		TimestampUTC:            time.Now().UTC().Format(time.RFC3339Nano),
		LocalQueueDepth:         depth + memoryDepth,
		DatabaseSizeBytes:       spoolBytes,
		Status:                  status,
		WorkingSetBytes:         metrics.ProcessRSSBytes,
		CPUPercentEstimate:      metrics.CPUPercent,
		HostIP:                  a.hostIP,
		CentralURL:              a.cfg.Central.URL,
		Platform:                "linux",
		LastError:               truncate(a.getLastError(), 512),
		BinarySHA256:            a.binarySHA256,
		MemUsedPercent:          metrics.MemUsedPercent,
		DiskUsedPercent:         metrics.DiskUsedPercent,
		NetworkRXBytesPerSecond: metrics.NetworkRXBPS,
		NetworkTXBytesPerSecond: metrics.NetworkTXBPS,
		LoadAverage1:            metrics.LoadAverage1,
		MetricsSummary:          summary,
	}
	if metrics.MemTotalBytes > 0 {
		total, used := metrics.MemTotalBytes, metrics.MemUsedBytes
		hb.HostMemTotalBytes = &total
		hb.HostMemUsedBytes = &used
	}
	response, err := a.transport.SendHeartbeat(ctx, hb)
	if err != nil {
		a.setLastError("heartbeat: " + err.Error())
		a.logger.Printf("heartbeat failed: %v", err)
	} else {
		a.clearLastErrorPrefix("heartbeat:")
		a.logger.Printf("heartbeat accepted skew=%.1fs %s", response.ClockSkewSeconds, summary)
	}
	a.writeStatus(status, summary, depth+memoryDepth, spoolBytes, dropped)
}

func (a *Agent) addEvents(items []model.SecurityEventRecord) {
	a.bufMu.Lock()
	defer a.bufMu.Unlock()
	a.events = append(a.events, items...)
	a.enforceMemoryLimitLocked()
}

func (a *Agent) addConnections(items []model.NetworkConnectionRecord) {
	a.bufMu.Lock()
	defer a.bufMu.Unlock()
	a.connections = append(a.connections, items...)
	a.enforceMemoryLimitLocked()
}

func (a *Agent) addAlerts(items []model.DetectionAlert) {
	a.bufMu.Lock()
	defer a.bufMu.Unlock()
	a.alerts = append(a.alerts, items...)
	a.enforceMemoryLimitLocked()
}

func (a *Agent) enforceMemoryLimitLocked() {
	maxItems := a.cfg.Collection.MaxMemoryItems
	for len(a.events)+len(a.connections)+len(a.alerts) > maxItems {
		switch {
		case len(a.connections) > 0:
			a.connections = a.connections[1:]
		case len(a.events) > 0:
			a.events = a.events[1:]
		case len(a.alerts) > 0:
			a.alerts = a.alerts[1:]
		default:
			return
		}
		a.dropped++
	}
}

func (a *Agent) setLastError(value string) {
	a.stateMu.Lock()
	a.lastError = truncate(value, 1024)
	a.stateMu.Unlock()
}

func (a *Agent) clearLastErrorPrefix(prefix string) {
	a.stateMu.Lock()
	if strings.HasPrefix(a.lastError, prefix) {
		a.lastError = ""
	}
	a.stateMu.Unlock()
}

func (a *Agent) getLastError() string {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.lastError
}

func (a *Agent) writeStatus(status, summary string, queueDepth, spoolBytes, dropped int64) {
	payload := map[string]any{
		"updated_at_utc": time.Now().UTC().Format(time.RFC3339Nano),
		"agent_id":       a.agentID,
		"computer_name":  a.computerName,
		"version":        a.version,
		"platform":       "linux-centos6",
		"status":         status,
		"metrics":        summary,
		"queue_depth":    queueDepth,
		"spool_bytes":    spoolBytes,
		"dropped_items":  dropped,
		"last_error":     a.getLastError(),
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	data = append(data, '\n')
	path := filepath.Join(a.cfg.Paths.StateDir, "status.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err == nil {
		_ = os.Rename(tmp, path)
	}
}
