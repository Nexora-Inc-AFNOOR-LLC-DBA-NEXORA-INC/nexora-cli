# Data Collected

## Summary

**nexora-cli collects no data. Zero.**

- No telemetry
- No analytics
- No usage tracking
- No error reporting to external services
- No phone-home of any kind

## What Stays Local

All of the following remain entirely on your machine or CI runner:

- Scanned file contents
- Findings and reports
- Evidence bundles
- GitHub tokens (used only for API calls, never stored or logged)

## Network Access

The **only** network access nexora-cli performs is:

| Command | Destination | Purpose |
|---------|-------------|---------|
| `nexora scan github` | `api.github.com` | Fetch workflow files |

All other commands (`scan k8s`, `scan iac`, `report`, `verify bundle`) make **zero network calls**.

## Verification

You can verify this claim by:
1. Reviewing the source code — it is fully open-source
2. Running `nexora scan k8s --path ./k8s/` with network blocked — it works fine
3. Inspecting the binary with a network monitoring tool
