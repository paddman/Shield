# NT Shield Layered Antivirus

Windows Agent 1.3 adds a user-mode endpoint protection pipeline:

```text
hash/signature + YARA + Microsoft Defender
        ↓
behavior and heuristic features
        ↓
Brain per-asset ML anomaly baseline
        ↓
AI evidence correlation
        ↓
incident score and Central policy decision
```

## Runtime behavior

- Real-time file notifications, on-demand `ScanFile`/`ScanPath`, and scheduled scans are supported.
- Microsoft Defender is used through `MpCmdRun.exe` when available.
- YARA rules are loaded from the protection pack. Put an approved `tools/yara64.exe` beside the Agent executable; if it is absent, the Agent reports degraded YARA protection and continues with Defender/signature/heuristic layers.
- The default mode is detect-only. `QuarantineFile` and `RestoreQuarantinedFile` require an approved Central action.
- Quarantine metadata and the file are stored under `C:\ProgramData\NTShield\Agent\protection\quarantine` with a restricted ACL where Windows permits it.

## Signed protection packs

`config/protection-pack.json` is a local bootstrap pack. Central updates use:

```http
PUT /api/v1/protection-pack
```

The request must include a newer pack version, the SHA-256 of the exact `payloadJson`, and an RSA PKCS#1 SHA-256 signature. Configure the matching public key in the Agent's `Antivirus:ProtectionPublicKeyPem` and Central's `Security:PolicySigningPublicKeyPem`. Agents reject missing/invalid signatures, bad hashes, and downgrades.

The signed payload contains `hashSignatures` and `yaraRules`. It is bounded to 2 MB and is written atomically before activation.

## Safety boundary

This is a layered user-mode EPP integration, not a kernel minifilter or a replacement for Microsoft Defender. It does not claim boot-sector, rootkit, memory-only, or full exploit prevention coverage. AI can enrich and correlate evidence, but cannot directly approve destructive actions.
