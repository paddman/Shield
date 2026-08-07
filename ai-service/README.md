# NT Shield Brain

**Evidence-grounded AI SOC analyst for NT Shield, Suricata, Zeek and Attack Surface telemetry.**

NTShield Brain turns many low-level alerts into one explainable incident decision. It combines deterministic risk rules, per-asset anomaly detection, local Qwen analysis, playbook retrieval, a threat graph, guarded response recommendations, bounded read-only investigation, multi-tenant API keys, feedback and usage metering.

## What is implemented

- **Local Qwen through an OpenAI-compatible API** such as vLLM, SGLang or an internal model gateway.
- **Multi-agent analysis mode** with Network, Endpoint and Exposure specialists plus an Incident Commander.
- **Hybrid risk engine** that anchors the model to deterministic evidence and limits unsupported score changes.
- **ML behavioral baseline** per tenant and asset using Isolation Forest plus robust median absolute deviation.
- **Evidence guardrails**: the model may cite only supplied `ref_id` values. Unknown citations are discarded.
- **Response guardrails**: only allowlisted actions are returned. Blocking, isolation, account, process and service actions always require human approval.
- **Bounded Investigation Agent** with a hard wall-clock deadline and four read-only tools: approved IOC aggregate, same-tenant analysis history, related NT Shield Central incidents and local playbook search.
- **Threat graph** linking hosts, IPs, users, processes, services, domains, IDS alerts, ASM findings, CVEs and deception hits.
- **Silent Hunter deception tokens** for canary credentials, honey files, decoy API keys, URLs and shares; a hit becomes a critical AI-analyzed incident.
- **Approved IOC Exchange** for public IP, public domain and SHA-256 aggregates without returning tenant identities.
- **Local playbook RAG** using TF-IDF over defensive playbooks, with no external data dependency.
- **Monthly AI report**, **read-only threat-hunt planner**, analyst feedback and per-tenant usage metering.
- **NT Shield Central bridge** that can fetch an existing incident by ID without changing the .NET server first.
- **Deterministic fallback** so the demo still works when the LLM endpoint is unavailable.
- **Controlled acceptance harness** with six repeatable security scenarios and citation/action checks.

## Start in Docker

From the repository root:

```bash
cp ai-service/.env.example .env
# Edit .env: tenant key, NT Shield Central URL/API key and Qwen endpoint.
docker compose -f docker-compose.ai.yml up -d --build
curl http://127.0.0.1:8088/health
```

Default service port: `8088`. Docker runs the extended application `app.main_v2:app`.

## Start for development

```bash
cd ai-service
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

pip install -e ".[dev]"
uvicorn app.main_v2:app --host 0.0.0.0 --port 8088 --reload
pytest
```

Open API documentation at `http://127.0.0.1:8088/docs`.

## Tenant authentication and roles

All protected `/v1/*` endpoints require:

```text
X-NTShield-Tenant: demo
X-NTShield-Api-Key: change-me
```

Configure tenants with `NTSHIELD_TENANTS_JSON`:

```json
[
  {
    "tenant_id": "hospital-a",
    "name": "Hospital A",
    "api_key_sha256": "<sha256 of tenant API key>",
    "central_url": "https://10.0.0.5:7443",
    "central_api_key": "<NT Shield Central operator key>",
    "central_verify_tls": false,
    "metadata": {
      "role": "operator",
      "principal": "soc-analyst-01",
      "can_publish_intel": true
    }
  }
]
```

Use `api_key_sha256` rather than plaintext `api_key` in production. The Central URL comes only from server-side tenant configuration, preventing callers from turning the bridge into an arbitrary URL fetcher.

Cross-tenant IOC publication additionally requires `metadata.can_publish_intel=true` or an operator/SOC role. Ordinary tenant viewers may perform aggregate lookup but cannot publish observations.

## Analyze a combined incident

```bash
curl -X POST http://127.0.0.1:8088/v1/incidents/analyze \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  --data @../examples/ai-incident-password-spray.json
```

The request may combine:

- NT Shield endpoint incident and Windows event evidence
- Suricata alerts
- Zeek connection, DNS, HTTP, TLS, notice and weird records
- ASM results from subfinder, amass, naabu, nmap, httpx and nuclei
- threat-intelligence verdicts
- deception hits
- numerical behavioral features

The response includes Thai and English summaries, risk and confidence, MITRE mapping, exact evidence citations, specialist findings, a threat graph and guarded actions.

## Run a bounded investigation

```bash
curl -X POST http://127.0.0.1:8088/v1/investigations/run \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  -d '{
    "incident": {
      "incidentId": "inc-1001",
      "title": "Potential port scan",
      "severity": "High",
      "sourceIp": "198.51.100.24",
      "destinationIp": "203.0.113.20"
    },
    "maxSteps": 4,
    "maxRuntimeSeconds": 20
  }'
```

The planner cannot add arbitrary tools. Every call records its reason, duration, result and evidence references. The whole request is wrapped in a hard deadline; a connector or model that exceeds it receives HTTP `504` rather than silently running forever, a charming habit shared by less disciplined agents.

## Approved IOC exchange

Publication requires operator metadata plus explicit analyst approval in the payload:

```bash
curl -X POST http://127.0.0.1:8088/v1/intel/observations \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  -d '{
    "indicatorType": "domain",
    "indicator": "malicious.example",
    "incidentId": "inc-1001",
    "riskScore": 91,
    "confidence": 0.94,
    "approved": true,
    "approvedBy": "soc-analyst-01",
    "tags": ["c2"]
  }'
```

Lookup returns aggregate counts, dates, risk/confidence and tags, never customer identity:

```bash
curl -G http://127.0.0.1:8088/v1/intel/lookup \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  --data-urlencode 'indicator_type=domain' \
  --data-urlencode 'indicator=malicious.example'
```

Only public/global IPs, public domains and SHA-256 hashes may be shared. Private IPs, internal domains, usernames, hostnames and payloads are rejected or never exposed.

## Analyze an incident already stored in NT Shield Central

```bash
curl -X POST http://127.0.0.1:8088/v1/central/incidents/INCIDENT_ID/analyze \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me'
```

The tenant must have `central_url` and `central_api_key` configured.

## Train and score an asset baseline

Send normal observations with `learn: true`:

```bash
curl -X POST http://127.0.0.1:8088/v1/anomaly/observe \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  -d '{
    "asset_id": "web-01",
    "learn": true,
    "features": {
      "connections_per_minute": 95,
      "unique_destination_ports": 4,
      "failed_login_rate": 0,
      "dns_query_entropy": 2.1
    }
  }'
```

After the minimum sample count, the response switches from `learning` to `ready`. Very strong outliers are not written back into the stable baseline, reducing baseline poisoning.

## Silent Hunter deception token

Create a token from an authenticated SOC session:

```bash
curl -X POST http://127.0.0.1:8088/v1/deception/tokens \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  -d '{"name":"Finance backup credential","tokenType":"canary_credential","asset":"backup-vault","ttlDays":365}'
```

The raw token is returned exactly once. Put it only in an authorized decoy location. A sensor reports access with:

```bash
curl -X POST http://127.0.0.1:8088/v1/deception/hits \
  -H 'Content-Type: application/json' \
  -d '{"token":"<raw token>","sourceIp":"10.9.0.7","sourceHost":"srv-x","processName":"powershell.exe","destination":"backup-vault"}'
```

The hit endpoint deliberately does not reveal whether a token was valid. Valid hits are deduplicated, stored, converted into a critical incident and analyzed through the same evidence and approval guardrails.

## Qwen configuration

```env
NTSHIELD_LLM_BASE_URL=http://10.0.0.20:8000/v1
NTSHIELD_LLM_API_KEY=local
NTSHIELD_LLM_MODEL=qwen3.5:9b
NTSHIELD_ANALYSIS_MODE=multi_agent
NTSHIELD_LLM_ENABLE_THINKING=false
```

`multi_agent` runs three specialists in parallel and then one commander synthesis. Use `single` when low latency matters more than the extra analysis pass.

### Route the Brain through Central LLM Gateway

After creating a token in **Control Center → LLM Gateway**, the Brain can use Central as its only model endpoint. The Central server validates the token and forwards the request to the configured upstream model server:

```env
NTSHIELD_LLM_BASE_URL=https://<CENTRAL>:7443/api/v1/llm/v1
NTSHIELD_LLM_API_KEY=ntllm_<issued-token>
NTSHIELD_LLM_MODEL=qwen3.5:9b
```

Do not put the Central token in a committed file. Keep it in the deployment environment or an ignored `.env` file.

## Controlled acceptance evaluation

The repository ships six version-controlled scenarios: reconnaissance, credential attack, remote access/tunnel, web compromise, deception and benign control.

```bash
python scripts/evaluate_acceptance.py \
  --suite evaluation/acceptance-suite.json \
  --out acceptance-report.json
```

The default run disables the LLM for deterministic CI reproducibility and checks:

- risk range and expected attack stage
- exact citation validity
- absence of forbidden actions
- mandatory approval for destructive actions
- p50/p95 analysis latency

Use `--use-llm` to measure the configured local Qwen deployment. Those results depend on model server, GPU and queue state and should be reported separately from deterministic CI.

## Main API

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service and local model reachability |
| GET | `/v1/status` | Tenant, model and guardrail state |
| GET | `/v1/readiness` | Implemented vs pilot-validation boundary |
| POST | `/v1/incidents/analyze` | Analyze a combined XDR incident |
| POST | `/v1/investigations/run` | Run bounded read-only investigation with trace |
| POST | `/v1/central/incidents/{id}/analyze` | Pull and analyze a NT Shield Central incident |
| GET | `/v1/analyses/{incident_id}` | Retrieve the latest stored decision |
| POST | `/v1/intel/observations` | Publish an operator-approved IOC observation |
| GET | `/v1/intel/lookup` | Read privacy-preserving cross-tenant aggregate |
| POST | `/v1/anomaly/observe` | Learn/score per-asset behavior |
| POST | `/v1/feedback` | Store analyst verdict for later calibration |
| POST/GET | `/v1/deception/tokens` | Create or list defensive canary tokens |
| POST | `/v1/deception/hits` | Sensor callback; token acts as bearer secret |
| POST | `/v1/hunt/plan` | Create a read-only threat-hunt plan |
| POST | `/v1/reports/monthly` | Generate executive and technical summaries |
| GET | `/v1/playbooks/search` | Search local defensive playbooks |
| GET | `/v1/usage/{yyyy-mm}` | Tenant AI usage and token metering |

## Safety model

NTShield Brain cannot run arbitrary shell commands or execute response actions. It returns declarative recommendations only. NT Shield Central remains the execution and operator-approval boundary. Even when a model tries to mark a destructive action as automatic, the service rewrites it to `requires_human_approval: true`.

Current POC tenant isolation is logical. Production requires PostgreSQL row-level security or per-tenant schema/database, distributed rate limiting, retention enforcement, capacity tests and security review before an MDR SLA is advertised.
