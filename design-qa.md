# Threat Campaigns — Design QA

- Source visual truth: `/home/adminmc/.codex/generated_images/019fdbbf-fdbf-73b0-b9ec-dd77875d5476/exec-364303b2-71e9-420a-ac29-ead851e08de4.png`
- Selected visual direction: option 2, Correlation Theater
- Intended viewport: 1440 × 1024 desktop
- Intended state: authenticated NT Shield Control Center, `Threat Campaigns`, populated selected campaign
- Implementation: production Central at `https://127.0.0.1:7443/`, served assets verified with HTTP 200
- Implementation screenshot: not captured; no browser-rendering/capture tool is available in this environment
- Pixel/density normalization: not applicable; rendered screenshot unavailable

## Evidence available

- Server build passed with no compile errors.
- Production health endpoint returned HTTP 200.
- `threat-campaign.css` and cache-busted `app.js` returned HTTP 200.
- Central service is active with no error-priority entries after restart.
- Threat data endpoint contains populated campaigns with hops, hosts, IPs, users and timestamps.

## Findings

Visual comparison is blocked because the implementation cannot be opened and captured in a browser from this environment. Static/runtime checks cannot verify typography rendering, spacing at 1440 × 1024, responsive behavior, hover/selected states, or browser console errors.

## Open Questions

- Confirm the selected campaign graph and timeline visually after login.
- Confirm the 24-hour filter behavior against the operator's current browser clock.

## Implementation Checklist

- [x] Campaign rail with severity filter and sorting
- [x] Selected campaign attack graph built from real `ThreatHop` data
- [x] Campaign facts and indicators inspector
- [x] Correlation timeline from hop timestamps
- [x] Empty state for no campaign/no path
- [x] Responsive layout for narrower screens
- [x] Production deployment and static/runtime checks
- [ ] Browser screenshot comparison and console-error check

**final result: blocked**
