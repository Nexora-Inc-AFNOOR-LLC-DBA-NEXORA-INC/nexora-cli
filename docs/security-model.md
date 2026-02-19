# Security Model

## Design Principles

1. **Read-only** — nexora-cli never writes to scanned targets
2. **No execution** — scanned content is never executed (`os/exec` is absent from all scanners)
3. **No network in file scans** — only `nexora scan github` makes network calls
4. **No telemetry** — zero data leaves the machine
5. **Deterministic** — same input always produces same findings and fingerprints
6. **DoS-resistant YAML parsing** — file size, depth, and node count limits enforced

## Input Validation

- Max YAML file size: 10MB
- Max YAML node depth: 200
- Max total YAML nodes per file: 200,000
- Files exceeding limits are skipped with a WARN log; scan continues

## Secret Handling

- Secrets detected in findings are redacted in `Evidence` fields before output
- Redaction uses deterministic patterns (no high-entropy heuristics)
- Redaction is applied to: `Finding.Evidence`, SARIF `message.text`, OCSF `finding_info.desc`
- Redaction is NOT applied to: file paths, rule IDs, checksums, structural fields

## Evidence Bundle Integrity

- SHA-256 and SHA-512 per file
- `files_root_hash` = SHA-256 of canonical JSON of sorted file entries
- `nexora verify bundle` recomputes all hashes and exits non-zero on any mismatch
- Bundles do NOT contain digital signatures (use cosign on release artifacts)

## GitHub Token Handling

- Token accepted via `--token` flag or `GITHUB_TOKEN` environment variable
- Token is used only for GitHub API calls
- Token is never logged (zerolog WARN/ERROR messages do not include token values)
- Token is never written to disk
- Token is never sent to any Nexora system

## SaaS Boundary

This tool contains zero Nexora SaaS logic. There are no:
- Internal Nexora API endpoints
- ML models or behavioral detection
- Multi-tenant engine components
- Telemetry or analytics collectors
