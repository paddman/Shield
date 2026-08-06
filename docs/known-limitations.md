# Known Limitations

0. **API auth default off**
   `Security:RequireAuth` defaults to **false** for lab upgrade safety. Enable after distributing `EnrollmentToken` / `OperatorApiKey` from `secrets.json`. See `docs/security-auth-policy.md`.

1. **.NET 10 on Windows Server 2012/2012 R2**
   Collector code uses 2012-era Win32 APIs, but the .NET 10 runtime support matrix may not list 6.2/6.3. Always validate on golden images with self-contained publish + VC++ Redistributable.

2. **IPv6 TCP table parsing**
   `GetExtendedTcpTable` IPv6 rows use a different layout; current collector fully parses IPv4 and best-effort skips incomplete IPv6 structures.

3. **Event bookmark**
   Resume uses `EventRecordId` state, not binary `EventBookmark` blobs (more portable across restarts).

4. **Process signature**
   Uses Authenticode certificate extraction; catalog-only signatures may report unsigned.

5. **Quarantine host**
   Full host quarantine on Server 2012 is limited to netsh advfirewall rules; NAC/firewall integration is recommended for production isolation.

6. **Response without approval**
   Default DetectOnly logs only. Operators must approve via Central `POST /api/v1/actions` with `approved=true`.

7. **CPU/memory targets**
   Design targets (&lt;2% CPU steady, &lt;150 MB) depend on event volume and hash options; disable executable hashing on constrained hosts if needed.

8. **PostgreSQL required for Central**
   Server starts without DB but ingest fails until PostgreSQL is available.

9. **Compression**
   Agent may gzip large ingest bodies; ensure reverse proxies forward `Content-Encoding`.

10. **No Security log clear / audit policy changes**
    By design the agent will not clear Security logs or auto-change audit policy.
