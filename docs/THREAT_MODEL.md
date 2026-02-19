# Threat Model

## Assets

| Asset | Description |
|-------|-------------|
| Scanned source files | Workflow YAML, K8s manifests, IaC files |
| GitHub token | Used only by `scan github`; read-only API access |
| Findings output | Structured findings; may contain partial credential snippets (redacted) |
| Evidence bundle | Integrity-checked archive of findings |

## Trust Boundaries

```
[Local filesystem / CI runner]
        |
        v
[nexora-cli binary]
        |
        +---> [File scanner] (no network, no exec)
        |
        +---> [GitHub API] (scan github only, read-only)
        |
        v
[stdout / output file / bundle dir]
```

## Threat Scenarios

### T1 — Malicious YAML file causes DoS
**Mitigation:** File size limit (10MB), node depth limit (200), total node limit (200,000). Files exceeding limits are skipped.

### T2 — Malicious YAML file causes code execution
**Mitigation:** `os/exec` is absent from all scanners. YAML is parsed into `yaml.Node` only — no unmarshalling into executable types.

### T3 — Credential leakage in findings output
**Mitigation:** `internal/redact` applies deterministic patterns to `Finding.Evidence` before any output. Redaction covers GitHub tokens, AWS keys, and PEM private keys.

### T4 — Supply chain attack via unpinned CI actions
**Mitigation:** All CI workflow actions are pinned to full commit SHAs. GoReleaser produces SBOM (SPDX JSON) and cosign keyless signatures for release artifacts.

### T5 — Evidence bundle tampering
**Mitigation:** `manifest.json` contains SHA-256 + SHA-512 per file and a `files_root_hash`. `nexora verify bundle` recomputes and exits non-zero on mismatch.

### T6 — GitHub token exfiltration
**Mitigation:** Token is never logged, never written to disk, never sent to any Nexora system. Used only for GitHub API calls within the `scan github` command.

### T7 — Nexora SaaS data exposure
**Mitigation:** This tool contains zero Nexora SaaS logic, no internal endpoints, no telemetry. The SaaS/CLI boundary is absolute and enforced by code review and CODEOWNERS.

## Out of Scope

- Runtime compromise of the machine running nexora-cli
- GitHub API credential theft via network interception (use HTTPS; standard TLS)
- Findings accuracy (false positives/negatives are a quality concern, not a security concern)
