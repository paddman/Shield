# Known Limitations

0. **Secure defaults require credential rollout**
   New Central configuration defaults to `Security:RequireAuth=true`. Existing installations that explicitly retain `RequireAuth=false` no longer expose operator APIs, but agents still need per-agent keys unless the separate dangerous lab switch `AllowLegacyAnonymousAgentIngest=true` is enabled. Distribute `EnrollmentToken` and the Control Center `OperatorApiKey` from protected `secrets.json` before production rollout.

1. **Signed-action replay ledger**
   Destructive actions are now target-bound, short-lived and RSA-signed. Central removes invalid, expired or tampered actions before delivery and the agent verifies the envelope through the `Approved` property. A persistent per-agent nonce/request replay ledger is still required for defense against deliberate replay of the same valid envelope inside its short validity window.

2. **Windows secrets ACL**
   Unix-like Central deployments attempt to set `secrets.json` mode to `0600`. Windows installers must enforce an ACL allowing only SYSTEM and Administrators on `C:\ProgramData\NTShield\Server`; the bootstrapper does not replace inherited Windows ACLs at runtime.

3. **Agent binary trust is optional until releases are code-signed**
   Heartbeats report binary SHA-256 and signing state, but `RequireSignedAgent` remains false by default so unsigned development builds can enroll. Enable it only after release signing, golden-image validation and rollback testing.

4. **.NET 10 on Windows Server 2012/2012 R2**
   Collector code uses 2012-era Win32 APIs, but the .NET 10 runtime support matrix may not list Windows 6.2/6.3. Always validate on golden images with self-contained publish plus the required VC++ runtime.

5. **IPv6 TCP table parsing**
   `GetExtendedTcpTable` IPv6 rows use a different layout; the current collector fully parses IPv4 and best-effort skips incomplete IPv6 structures.

6. **Event bookmark**
   Resume uses `EventRecordId` state, not binary `EventBookmark` blobs. This is more portable across restarts but requires care after log rollover or clear operations.

7. **Process signature**
   The endpoint pipeline uses Authenticode certificate extraction; catalog-only signatures may report unsigned.

8. **Quarantine host**
   Full host quarantine on Windows Server 2012 is limited to Windows Firewall rules. NAC or upstream firewall integration is recommended for production isolation, and the management path to Central must be preserved.

9. **Response policy**
   IDS/DetectOnly remains the safe endpoint default. Destructive Central actions require operator authentication, a concrete target agent and a valid short-lived RSA approval envelope. Automatic local IPS still depends on explicit policy and severity thresholds.

10. **CPU/memory targets**
    Design targets below 2% steady CPU and 150 MB memory depend on event volume, hashing and file monitoring. Disable expensive executable hashing on constrained legacy hosts only after measuring the resulting loss of evidence.

11. **Central database scale**
    SQLite is suitable for lab and small deployments. PostgreSQL or ClickHouse-backed deployment is required for larger multi-tenant workloads, and PostgreSQL row-level security or schema/database isolation remains a production requirement.

12. **Compression and reverse proxies**
    Agents may gzip large ingest bodies. Reverse proxies must forward `Content-Encoding` and preserve request bodies correctly.

13. **No Security log clear**
    By design the agent never clears Windows Security logs. Audit policy changes are limited to explicitly configured PowerShell telemetry and should be controlled through deployment policy.
