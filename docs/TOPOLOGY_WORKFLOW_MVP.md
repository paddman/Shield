# Topology Canvas and Detection Workflow MVP

The Central Control Center now includes a tenant-scoped infrastructure map and
declarative detection workflow graph. It is designed as the first vertical
slice for the customer workspace described in the platform plan.

## Included

- Asset catalog for customer-owned systems that do not run an NT Shield Agent.
- SVG/HTML Canvas editor with node drag, connect mode, delete mode, zoom and fit.
- Node types for Internet, DNS, CDN, WAF/AI-WAF, API Gateway, Load Balancer,
  Web/API, database, cache/queue, endpoint, Kubernetes, router, switch,
  firewall, VPN, Mikrotik, identity, Suricata/Zeek/EDR, cloud and backup.
- Tenant-filtered persistence for SQLite and PostgreSQL. ClickHouse mode keeps
  these transactional records in its existing SQLite control plane.
- Detection workflow graph nodes for Trigger, Filter, Enrich, Correlate,
  AI Analyst, Operator Approval, Response Proposal and Notify/Report.
- Validation for graph limits, dangling edges, self-loops, tenant asset links
  and workflow-to-topology links.

## API

All endpoints accept `X-NTShield-Tenant`; when it is omitted the existing
single-tenant dashboard uses `default`.

```text
GET    /api/v1/topology/kinds
GET    /api/v1/assets
POST   /api/v1/assets
PUT    /api/v1/assets/{id}
DELETE /api/v1/assets/{id}

GET    /api/v1/topologies
GET    /api/v1/topologies/{id}
POST   /api/v1/topologies
PUT    /api/v1/topologies/{id}
DELETE /api/v1/topologies/{id}

GET    /api/v1/workflows
GET    /api/v1/workflows/{id}
POST   /api/v1/workflows
PUT    /api/v1/workflows/{id}
DELETE /api/v1/workflows/{id}
```

The workflow graph is currently a persisted contract and editor. Its execution
must continue through the existing detection, AI investigation and
human-approval guardrails; this change does not silently enable automated
blocking or isolation.

## Next integration slices

1. Bind Agent, Syslog, Suricata/Zeek, WAF, Mikrotik and firewall connector
   identities to `TenantAsset` and `TopologyNode.TelemetrySourceIds`.
2. Resolve tenant from Central identity/RBAC claims instead of accepting a
   caller-selected header when shared operator keys are used.
3. Compile enabled workflow graphs into the existing rule/correlation pipeline,
   with simulation, versioning, approval policy and audit replay.
4. Overlay live incidents and threat campaigns on topology edges and produce
   customer-facing monthly reports.
