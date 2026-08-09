package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/config"
	"github.com/paddman/Shield/src/NTShield.Agent.CentOS6/internal/model"
)

func TestRegisterThenIngestUsesIssuedAPIKey(t *testing.T) {
	var gotKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agents/register":
			var req model.AgentRegistrationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.AgentID != "agent-1" || req.Platform != "linux" {
				t.Fatalf("bad registration: %#v", req)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":true,"message":"registered","agentApiKey":"issued-key"}`))
		case "/api/v1/ingest":
			gotKey = r.Header.Get("X-NTShield-Api-Key")
			if r.Header.Get("Idempotency-Key") != "idem-1" {
				t.Fatalf("missing idempotency key")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"accepted":true,"receivedCount":1,"createdIncidentIds":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := config.Default().Central
	cfg.URL = server.URL
	// The test TLS server uses an ephemeral self-signed certificate. Production
	// configuration keeps this false and supplies system trust or ca_file.
	cfg.InsecureSkipVerify = true
	client, err := New(cfg, filepath.Join(t.TempDir(), "api-key"), "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Register(context.Background(), model.AgentRegistrationRequest{AgentID: "agent-1", Platform: "linux"})
	if err != nil {
		t.Fatal(err)
	}
	batch := model.NewBatch("agent-1", "host", "test", "idem-1")
	batch.SecurityEvents = append(batch.SecurityEvents, model.SecurityEventRecord{RawXML: "test"})
	payload, _ := json.Marshal(batch)
	if _, err := client.SendBatch(context.Background(), payload, "idem-1"); err != nil {
		t.Fatal(err)
	}
	if gotKey != "issued-key" {
		t.Fatalf("got API key %q", gotKey)
	}
}

func TestClientRejectsPlainHTTP(t *testing.T) {
	cfg := config.Default().Central
	cfg.URL = "http://127.0.0.1:7443"
	if _, err := New(cfg, filepath.Join(t.TempDir(), "api-key"), "test-agent"); err == nil {
		t.Fatal("expected plain HTTP Central URL to be rejected")
	}
}
