# Known Limitations

This file is the boundary between what the repository enforces now and what still requires production engineering. A security product that hides this section is usually selling optimism by the kilogram.

0. **Existing installations need a controlled credential migration**
   New configuration defaults to `Security:RequireAuth=true`; operator APIs never become anonymous even when legacy mode is selected. Existing agents must receive an enrollment token or retain their issued per-agent key before Central is upgraded. The separate `AllowLegacyAnonymousAgentIngest=true` switch exists only for isolated migration labs and must not be used as a permanent compatibility setting.

1. **Operator identity is still a shared API key**
   The Control Center currently authenticates with one `OperatorApiKey`. Destructive actions are cryptographically signed, target-bound, expiring and replay-protected, but the approval actor is still the shared `operator` principal. Production MDR/SOC deployment still needs named users, MFA, RBAC, separation of duties and an approval record tied to an individual identity provider account.

2. **Action completion acknowledgement is not yet end-to-end**
   Agents persist local response results and Central audits enqueue/delivery decisions. A production workflow still needs an authenticated result callback with request id, before/after state, execution timestamp, error, rollback outcome and retry/dead-letter handling so Central can prove whether containment actually succeeded.

3. **Replay protection depends on protected Agent storage**
   Windows and Linux agents maintain a persistent nonce ledger so a signed action can execute only once, including across service restart. The Windows Agent data directory and Linux `/var/lib/ntshield` must remain writable only by the service identity/administrators. Installer ACL validation and tamper alarms should be expanded before hostile-local-user deployment.

4. **Non-installer Central deployments must protect secrets manually**
   The Windows installer restricts `secrets.json` and `central.pfx` to SYSTEM and built-in Administrators; Unix-like bootstrap attempts mode `0600`. Containers, copied binaries and custom service deployments must mount an equivalent protected secret volume and must never expose the Central action-signing private key to Agents, dashboards or backups with broad read access.

5. **Agent binary trust remains optional until release signing is operational**
   Heartbeats report binary SHA-256 and signing state, but `RequireSignedAgent` remains false by default so development builds can enroll. Enable it only after release binaries are code-signed, the approved hash/signing policy is distributed and rollback has been tested on golden images.

6. **Detection correlation is not yet fully stateful across all ingest windows**
   Endpoint rules, persisted telemetry and Central correlation cover credential attacks and lateral-movement evidence, but not every sequence is represented as a durable state machine across arbitrarily separated batches. Production validation must prove spray → success → privileged logon → remote execution chains across multiple endpoints and delayed/offline uploads.

7. **Ransomware monitoring is user-mode and evidence attribution is limited**
   File activity, entropy, extension and canary sensors can raise useful alerts, while Defender/YARA can scan files. This is not a kernel minifilter and does not yet provide reliable write-operation-to-process attribution on every Windows version. Do not claim deterministic real-time ransomware prevention from this layer alone.

8. **Windows Server 2012/2012 R2 requires golden-image validation**
   Collector code uses compatible-era Win32 APIs, but the .NET 10 runtime support matrix may not include Windows 6.2/6.3. Validate installation, service restart, HTTPS trust, event collection, response rollback and upgrade on actual supported images before contractual support.

9. **IPv6 network telemetry is incomplete**
   `GetExtendedTcpTable` IPv6 rows use a different layout; the current collector fully parses IPv4 and best-effort skips incomplete IPv6 structures. IPv6-heavy environments require additional collector and correlation testing.

10. **Event resume uses record ids rather than binary bookmarks**
    Collection resumes from `EventRecordId`, not serialized `EventBookmark` state. This is portable but needs explicit handling and health alerts after event-log rollover, replacement or clear operations.

11. **Process signing evidence has catalog-signature gaps**
    The endpoint pipeline extracts Authenticode certificate information; binaries signed only through a Windows catalog may appear unsigned. Treat signing state as one signal, not a standalone malicious verdict.

12. **Host isolation is not yet a production NAC control**
    Windows Server 2012 quarantine is limited to Windows Firewall behavior. Production isolation should preserve the Agent-to-Central management path and integrate with an approved NAC, EDR, firewall or cloud security-group connector with tested rollback.

13. **Local IPS remains explicitly policy-controlled**
    IDS/DetectOnly is the endpoint default. Central destructive actions require authenticated operator access, a concrete target Agent, RSA-PSS approval, expiry and one-time nonce reservation. Local automatic IPS is a separate policy decision and still requires tuned thresholds, allowlists and failure-safe rollback.

14. **Performance targets are not contractual measurements**
    CPU, memory, queue depth and latency depend on event volume, hashing, file monitoring, database provider and model deployment. Publish measured p50/p95 ingest, detection and containment latency before attaching an SLA.

15. **Multi-tenant storage isolation is not production-complete**
    SQLite is suitable for lab and small deployments. Larger service deployments require PostgreSQL/ClickHouse capacity validation and database-enforced tenant isolation such as PostgreSQL RLS, separate schemas or separate databases with automated cross-tenant access tests.

16. **Reverse proxies must preserve security semantics**
    Agents may send compressed ingest bodies. A reverse proxy must preserve `Content-Encoding`, client address, request size limits and HTTPS identity, and must not terminate authentication by exposing protected Central routes on another anonymous listener.

17. **The Agent never clears Security logs**
    By design the Agent does not clear Windows Security logs or offer arbitrary shell execution. PowerShell telemetry changes must be controlled through deployment policy and reviewed for operational/privacy impact.
