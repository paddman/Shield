# Windows AI realtime console

The Agent Tray now includes **Open AI realtime console**. It is a read-only SOC
window showing:

- local Agent and Central connectivity;
- Brain health and LLM model reachability;
- recent Brain analyses, risk score, confidence and model;
- Thai/English summary, attack chain, MITRE techniques, evidence references,
  unknowns and recommended actions.

The window refreshes every five seconds by default. It never executes response
actions; quarantine, blocking, isolation and process changes remain approval-
gated in Central.

## Configuration

Edit the `AiConsole` section in the Agent `appsettings.json`:

```json
{
  "AiConsole": {
    "Enabled": true,
    "BrainUrl": "http://127.0.0.1:8088",
    "TenantId": "tenant-id",
    "ApiKey": "set-outside-source-control",
    "RefreshSeconds": 5
  }
}
```

For production, prefer environment variables so the API key is not stored in
the file:

```text
NTSHIELD_BRAIN_URL
NTSHIELD_BRAIN_TENANT
NTSHIELD_BRAIN_API_KEY
```

If Brain or the LLM is unavailable, the window clearly reports offline status;
the Windows Agent and local Defender pipeline continue operating independently.
