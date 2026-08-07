# NTShield Brain AI

NT Shield now has a deployable **Sovereign AI-XDR / SOC-as-a-Service** layer under [`ai-service/`](ai-service/README.md).

It combines:

- local Qwen through an OpenAI-compatible endpoint
- Network, Endpoint and Exposure specialists plus an Incident Commander
- explainable deterministic risk and per-asset Isolation Forest baseline
- exact evidence citations, playbook RAG and a real-time threat graph payload
- guarded human-approved response recommendations
- Silent Hunter deception tokens
- multi-tenant keys, feedback, audit and usage metering
- Central LLM Gateway with expiring Agent tokens and server-side upstream forwarding
- NT Shield Central incident bridge
- monthly report and read-only threat-hunt APIs

Start it:

```bash
cp ai-service/.env.example .env
docker compose -f docker-compose.ai.yml up -d --build
curl http://127.0.0.1:8088/health
```

Analyze the bundled multi-source incident:

```bash
curl -X POST http://127.0.0.1:8088/v1/incidents/analyze \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  --data @examples/ai-incident-password-spray.json
```

Full architecture and dashboard integration: [`docs/ntshield-brain-ai.md`](docs/ntshield-brain-ai.md).

For the Central-side token management page and proxy route, see the root README section [LLM Gateway flow](README.md#llm-gateway-flow).
