package agent

import (
	"context"
	"encoding/json"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
)

func (a *Agent) pollConnections() {
	connections, err := a.procNet.Collect(a.agentID, a.computerName)
	if err != nil {
		a.setLastError("proc net: " + err.Error())
		a.logger.Printf("network collector warning: %v", err)
	}
	if len(connections) > 0 {
		a.addConnections(connections)
		a.logger.Printf("network snapshot collected=%d", len(connections))
	}
}

func (a *Agent) flush(ctx context.Context) {
	for batches := 0; batches < 4; batches++ {
		batch, ok := a.takeBatch()
		if !ok {
			break
		}
		payload, err := json.Marshal(batch)
		if err != nil {
			a.restoreBatch(batch)
			a.setLastError("marshal batch: " + err.Error())
			return
		}
		if _, err := a.spool.Enqueue(batch.IdempotencyKey, payload); err != nil {
			a.restoreBatch(batch)
			a.setLastError("spool enqueue: " + err.Error())
			a.logger.Printf("cannot persist ingest batch: %v", err)
			return
		}
	}
	a.drainSpool(ctx, 10)
}

func (a *Agent) drainSpool(ctx context.Context, maxItems int) {
	items, err := a.spool.List()
	if err != nil {
		a.setLastError("spool list: " + err.Error())
		return
	}
	if len(items) > maxItems {
		items = items[:maxItems]
	}
	for _, item := range items {
		payload, err := a.spool.Read(item)
		if err != nil {
			a.setLastError("spool read: " + err.Error())
			return
		}
		var header struct {
			IdempotencyKey string `json:"idempotencyKey"`
		}
		_ = json.Unmarshal(payload, &header)
		response, err := a.transport.SendBatch(ctx, payload, header.IdempotencyKey)
		if err != nil {
			a.setLastError("ingest: " + err.Error())
			a.logger.Printf("Central unavailable; batch retained in spool: %v", err)
			return
		}
		if err := a.spool.Remove(item); err != nil {
			a.setLastError("spool remove: " + err.Error())
			return
		}
		a.clearLastErrorPrefix("ingest:")
		a.logger.Printf("ingest accepted count=%d incidents=%d duplicate=%v", response.ReceivedCount, len(response.CreatedIncidentIDs), response.Duplicate)
	}
}

func (a *Agent) takeBatch() (model.AgentIngestBatch, bool) {
	a.bufMu.Lock()
	defer a.bufMu.Unlock()
	if len(a.events) == 0 && len(a.connections) == 0 && len(a.alerts) == 0 {
		return model.AgentIngestBatch{}, false
	}
	batch := model.NewBatch(a.agentID, a.computerName, a.version+"-centos6", randomID())
	eCount := min(len(a.events), a.cfg.Collection.MaxBatchEvents)
	cCount := min(len(a.connections), a.cfg.Collection.MaxBatchConnections)
	aCount := min(len(a.alerts), a.cfg.Collection.MaxBatchEvents)
	batch.SecurityEvents = append(batch.SecurityEvents, a.events[:eCount]...)
	batch.NetworkConnections = append(batch.NetworkConnections, a.connections[:cCount]...)
	batch.Alerts = append(batch.Alerts, a.alerts[:aCount]...)
	a.events = append([]model.SecurityEventRecord(nil), a.events[eCount:]...)
	a.connections = append([]model.NetworkConnectionRecord(nil), a.connections[cCount:]...)
	a.alerts = append([]model.DetectionAlert(nil), a.alerts[aCount:]...)
	return batch, true
}

func (a *Agent) restoreBatch(batch model.AgentIngestBatch) {
	a.bufMu.Lock()
	defer a.bufMu.Unlock()
	a.events = append(batch.SecurityEvents, a.events...)
	a.connections = append(batch.NetworkConnections, a.connections...)
	a.alerts = append(batch.Alerts, a.alerts...)
}
