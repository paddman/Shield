package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/collector"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/parser"
)

func (a *Agent) Run(ctx context.Context, once bool) error {
	a.logger.Printf("starting agent version=%s id=%s host=%s os=%q central=%s", a.version, a.agentID, a.computerName, a.osVersion, a.cfg.Central.URL)
	if a.cfg.Central.InsecureSkipVerify {
		a.logger.Printf("WARNING: TLS certificate verification is disabled by configuration")
	}

	a.lastMetrics = a.metrics.Snapshot()
	a.register(ctx)

	var syslogCh <-chan collector.SyslogDatagram
	if a.cfg.Collection.Syslog.Enabled {
		ch, err := collector.ListenSyslog(ctx, a.cfg.Collection.Syslog.Listen, a.cfg.Collection.Syslog.MaxMessageBytes, a.logger)
		if err != nil {
			a.setLastError("syslog listen: " + err.Error())
			a.logger.Printf("syslog listener disabled after bind error on %s: %v", a.cfg.Collection.Syslog.Listen, err)
		} else {
			syslogCh = ch
			a.logger.Printf("syslog UDP listener active on %s", a.cfg.Collection.Syslog.Listen)
		}
	}

	// Initial collection. New log files start at EOF by default, preventing an
	// accidental upload of years of archives on a museum-grade operating system.
	a.pollLogs()
	a.pollConnections()
	a.flush(ctx)
	a.sendHeartbeat(ctx)
	if once {
		return nil
	}

	logTicker := time.NewTicker(time.Duration(a.cfg.Collection.LogPollSeconds) * time.Second)
	connTicker := time.NewTicker(time.Duration(a.cfg.Collection.ConnectionPollSeconds) * time.Second)
	flushTicker := time.NewTicker(time.Duration(a.cfg.Collection.FlushIntervalSeconds) * time.Second)
	heartbeatTicker := time.NewTicker(time.Duration(a.cfg.Collection.HeartbeatIntervalSeconds) * time.Second)
	defer logTicker.Stop()
	defer connTicker.Stop()
	defer flushTicker.Stop()
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.logger.Printf("shutdown requested")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			a.pollLogs()
			a.flush(shutdownCtx)
			a.sendHeartbeat(shutdownCtx)
			cancel()
			return nil
		case msg, ok := <-syslogCh:
			if !ok {
				syslogCh = nil
				continue
			}
			a.handleSyslog(msg.Payload, msg.RemoteAddr, msg.ReceivedAt, "udp")
		case <-logTicker.C:
			a.pollLogs()
		case <-connTicker.C:
			a.pollConnections()
		case <-flushTicker.C:
			a.lastMetrics = a.metrics.Snapshot()
			a.flush(ctx)
		case <-heartbeatTicker.C:
			a.lastMetrics = a.metrics.Snapshot()
			a.sendHeartbeat(ctx)
		}
	}
}

func (a *Agent) register(ctx context.Context) {
	unsigned := (*bool)(nil)
	request := model.AgentRegistrationRequest{
		AgentID:        a.agentID,
		ComputerName:   a.computerName,
		AgentVersion:   a.version + "-centos6",
		OSVersion:      a.osVersion,
		HostIP:         a.hostIP,
		BinarySHA256:   a.binarySHA256,
		IsBinarySigned: unsigned,
		Platform:       "linux",
	}
	regCtx, cancel := context.WithTimeout(ctx, time.Duration(a.cfg.Central.TimeoutSeconds)*time.Second)
	defer cancel()
	response, err := a.transport.Register(regCtx, request)
	if err != nil {
		a.setLastError("register: " + err.Error())
		a.logger.Printf("registration failed; offline spool remains active: %v", err)
		return
	}
	a.logger.Printf("registration accepted: %s", response.Message)
}

func (a *Agent) pollLogs() {
	lines, err := a.tailer.Read(a.cfg.Collection.LogFiles)
	if err != nil {
		a.setLastError("log tail: " + err.Error())
		a.logger.Printf("log tail warning: %v", err)
	}
	for _, line := range lines {
		a.handleSyslog(line.Text, "", line.ObservedAt, line.Path)
	}

	wafLines, err := a.tailer.Read(a.cfg.Collection.WAFLogFiles)
	if err != nil {
		a.setLastError("WAF tail: " + err.Error())
		a.logger.Printf("WAF tail warning: %v", err)
	}
	for _, line := range wafLines {
		for _, event := range a.waf.Feed(line.Path, line.Text, line.ObservedAt) {
			a.addWAFEvent(event, line.Path)
		}
	}
}

func (a *Agent) handleSyslog(raw, remote string, receivedAt time.Time, source string) {
	for _, one := range splitDatagram(raw) {
		if wafEvent, ok := parser.ParseWAF(one, receivedAt); ok {
			if wafEvent.SourceIP == "" {
				wafEvent.SourceIP = hostOnly(remote)
			}
			a.addWAFEvent(wafEvent, source)
			continue
		}
		msg := parser.ParseSyslog(one, receivedAt, remote)
		provider := msg.AppName
		if provider == "" {
			provider = filepath.Base(source)
		}
		if provider == "." || provider == "" {
			provider = "syslog"
		}
		status := "syslog"
		if msg.Facility >= 0 || msg.Severity >= 0 {
			status = fmt.Sprintf("facility=%d severity=%d", msg.Facility, msg.Severity)
		}
		event := model.SecurityEventRecord{
			TimestampUTC:    msg.Timestamp.UTC().Format(time.RFC3339Nano),
			ComputerName:    a.computerName,
			AgentID:         a.agentID,
			EventID:         9000,
			Channel:         "syslog",
			ProviderName:    provider,
			SourceIP:        msg.SourceIP,
			Status:          status,
			SubStatus:       truncate(strings.TrimSpace(msg.Message), 512),
			WorkstationName: msg.Hostname,
			RawXML:          truncate(one, a.cfg.Collection.MaxLineBytes),
			CollectedAtUTC:  time.Now().UTC().Format(time.RFC3339Nano),
		}
		if msg.ProcessID != "" {
			if pid, err := strconv.Atoi(msg.ProcessID); err == nil {
				event.ProcessID = &pid
			}
		}
		a.addEvents([]model.SecurityEventRecord{event})
	}
}

func (a *Agent) addWAFEvent(waf parser.WAFEvent, source string) {
	now := time.Now().UTC()
	timestamp := waf.Timestamp
	if timestamp.IsZero() {
		timestamp = now
	}
	var sourcePort *int
	if waf.SourcePort > 0 {
		value := waf.SourcePort
		sourcePort = &value
	}
	details := map[string]any{
		"provider":   waf.Provider,
		"rule_id":    waf.RuleID,
		"message":    waf.Message,
		"severity":   waf.Severity,
		"action":     waf.Action,
		"source_ip":  waf.SourceIP,
		"host":       waf.Host,
		"uri":        waf.URI,
		"unique_id":  waf.UniqueID,
		"log_source": source,
		"raw":        truncate(waf.Raw, a.cfg.Collection.MaxWAFEventBytes),
	}
	rawJSON, _ := json.Marshal(details)
	event := model.SecurityEventRecord{
		TimestampUTC:    timestamp.UTC().Format(time.RFC3339Nano),
		ComputerName:    a.computerName,
		AgentID:         a.agentID,
		EventID:         9100,
		Channel:         "waf",
		ProviderName:    waf.Provider,
		SourceIP:        waf.SourceIP,
		SourcePort:      sourcePort,
		Status:          waf.Action,
		SubStatus:       truncate(fmt.Sprintf("rule=%s %s", waf.RuleID, waf.Message), 512),
		WorkstationName: waf.Host,
		TaskName:        waf.URI,
		RawXML:          string(rawJSON),
		CollectedAtUTC:  now.Format(time.RFC3339Nano),
	}
	a.addEvents([]model.SecurityEventRecord{event})

	if waf.Severity >= 3 || waf.Action == "blocked" {
		evidence, _ := json.Marshal([]map[string]any{{
			"rule_id": waf.RuleID,
			"action":  waf.Action,
			"uri":     waf.URI,
			"host":    waf.Host,
			"source":  source,
		}})
		alert := model.DetectionAlert{
			AlertID:      randomID(),
			TimestampUTC: timestamp.UTC().Format(time.RFC3339Nano),
			ComputerName: a.computerName,
			AgentID:      a.agentID,
			RuleID:       "WAF_" + sanitizeRuleID(waf.RuleID),
			RuleName:     "Web Application Firewall event",
			Severity:     waf.Severity,
			Title:        truncate(fmt.Sprintf("WAF %s: %s", waf.Action, waf.Message), 240),
			Description:  truncate(fmt.Sprintf("provider=%s rule=%s source=%s host=%s uri=%s", waf.Provider, waf.RuleID, waf.SourceIP, waf.Host, waf.URI), 1024),
			SourceIP:     waf.SourceIP,
			EventCount:   1,
			EvidenceJSON: string(evidence),
		}
		a.addAlerts([]model.DetectionAlert{alert})
	}
}
