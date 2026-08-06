# NT SHIELD Implementation Readiness

This document is the honest implementation boundary for the NT AIaaS Hackathon proposal. It distinguishes what the repository can demonstrate now from what still needs pilot and production validation.

## Implemented and demonstrable

| Capability | Evidence in repository |
|---|---|
| Windows/Linux endpoint telemetry and response framework | NT Shield Agent, Central and installers |
| Cross-host authentication and process/service attribution | Central correlator and incident model |
| Suricata/Zeek/ASM evidence ingestion contract | NTShield Brain unified incident payload |
| Local Qwen analysis | OpenAI-compatible vLLM/SGLang/Ollama client |
| Evidence-grounded explanation | Exact `ref_id` validation and deterministic fallback |
| Behavioral anomaly detection | Per-tenant/per-asset Isolation Forest + robust MAD |
| Bounded investigation agent | Read-only allowlisted tools, maximum steps/time and full trace |
| Human approval boundary | Destructive recommendations are always approval-gated |
| Threat graph | Host/IP/user/process/service/domain/exposure graph payload |
| Deception | Approval-safe canary token registry and incident conversion |
| Cross-customer learning MVP | Analyst-approved aggregate IOC exchange without tenant identities |
| Reporting and hunting APIs | Monthly summary and read-only hunt planner |
| Audit and usage metering | Tenant-scoped SQLite audit, feedback and token/call counters |

## Pilot validation required

| Area | Current boundary | Exit criterion |
|---|---|---|
| Cross-layer production correlation | Data contract and bounded investigation exist; separate Suricata/Zeek web application must call the API | Controlled scenario produces one incident with clickable endpoint/network/firewall evidence |
| Multi-tenant database isolation | POC uses API key + `tenant_id` logical isolation | PostgreSQL RLS or per-tenant schema/database; automated isolation tests |
| Scheduled hunting/reporting | Planner and report API exist | Scheduler, retry/dead-letter queue, delivery audit and per-tenant quota |
| Firewall history connector | Read-only interface is planned per customer/firewall | At least one approved firewall connector with normalized evidence IDs |
| PCAP tool invocation | Existing dashboard can capture/replay; AI currently recommends and references evidence | Bounded capture API with duration/size limit, retention and operator policy |
| Capacity and latency | Unit tests pass; real local Qwen latency depends on deployment | Measured p50/p95 latency, queue depth, GPU utilization and cost per analyzed incident |
| Windows Server 2012/2012 R2 | Collector uses compatible-era APIs, but .NET runtime compatibility requires validation | Golden-image installation, service restart, event collection and rollback tests |
| Legal/privacy review | Technical minimization controls exist | Written approval from Legal/DPO and customer service terms |

## Cross-customer IOC exchange safety

Only analyst-approved `true_positive` observations may be published. The exchange accepts only:

- public/global IP addresses
- public domain names
- SHA-256 file hashes

Private IPs, internal domains, customer names, usernames, hostnames, packet payloads and tenant identities are rejected or never returned. Lookups expose aggregate counts, dates, risk/confidence and tags only.

## Investigation-agent safety

The bounded investigation endpoint exposes four read-only tools:

1. approved IOC aggregate lookup
2. prior analysis search within the same tenant
3. related incident lookup from that tenant's server-configured NT Shield Central
4. local defensive playbook search

The planner cannot add tools, repeat them indefinitely or exceed the configured step/time limit. It has no shell, arbitrary URL, scanner, firewall, account, process or service mutation capability. Final response actions remain recommendations behind NT Shield Central operator approval.

## Run the extended API

Docker uses `app.main_v2:app` and exposes:

```text
POST /v1/investigations/run
POST /v1/intel/observations
GET  /v1/intel/lookup
GET  /v1/readiness
```

The remaining NTShield Brain endpoints are unchanged.
