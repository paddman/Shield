# NT Shield Behavioral ML v2

The AI service now keeps independent behavioral baselines by:

```text
tenant + asset_id + profile + schema_version
```

This prevents authentication, process, network and resource metrics from being mixed into one model merely because they came from the same server. Humanity has already invented enough accidental data soups.

## Detection pipeline

1. Accept finite numerical features.
2. Learn a warm-up baseline.
3. Apply a robust median/MAD/IQR deviation guard during warm-up.
4. Train an Isolation Forest after the configured minimum sample count.
5. Fuse multivariate Isolation Forest, robust feature deviation and schema-drift scores.
6. Refuse to learn observations above the learning threshold, reducing baseline poisoning.
7. Cache trained models by tenant and scoped asset key, invalidating them when the baseline changes.

The original `POST /v1/anomaly/observe` endpoint remains compatible. It uses the same v2 engine with the default `generic` profile and `v1` schema. The extended endpoints are available through `app.main_v2:app`:

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/anomaly/behavioral/status` | Engine version, thresholds and cache state |
| GET | `/v1/anomaly/behavioral/baselines/{asset_id}` | Baseline state for one profile/schema |
| POST | `/v1/anomaly/behavioral/observe` | Detailed single-observation scoring |
| POST | `/v1/anomaly/behavioral/observe/batch` | Score up to 250 observations |

## Example

```bash
curl -X POST http://127.0.0.1:8088/v1/anomaly/behavioral/observe \
  -H 'Content-Type: application/json' \
  -H 'X-NTShield-Tenant: demo' \
  -H 'X-NTShield-Api-Key: change-me' \
  -d '{
    "assetId": "web-01",
    "profile": "network",
    "schemaVersion": "v1",
    "learn": true,
    "features": {
      "connections_per_minute": 95,
      "unique_destination_ports": 4,
      "failed_login_rate": 0
    }
  }'
```

The detailed response reports:

- overall anomaly score and decision threshold
- Isolation Forest, robust deviation and schema-drift component scores
- whether the observation was learned or rejected from the baseline
- top contributing features
- baseline sample count and model-cache hit state

## Recommended profiles

Use stable profile names such as `auth`, `process`, `network`, `service`, `resource`, `database`, `waf` and `dns`. Increment `schemaVersion` whenever the numerical feature definition changes. A new schema learns independently instead of quietly corrupting the old baseline, which is a surprisingly useful property for software.

## Operational boundary

This is unsupervised anomaly detection, not proof of compromise. Treat the result as a risk signal for correlation and analyst review. Production deployment still needs retention controls, model-quality monitoring, representative clean training windows and tenant-specific threshold calibration.
