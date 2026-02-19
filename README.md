# nexora-cli

**Open-source, read-only NHI (Non-Human Identity) risk scanner** by [Nexora](https://nexora.inc).

Scans GitHub Actions workflows, Kubernetes manifests, and IaC files for machine identity risk patterns. Produces structured findings in table, JSON, SARIF 2.1.0, and OCSF 1.1.0 formats.

## Key Properties

- **Read-only** — never writes to scanned targets
- **No network calls** for file-based scans (workflows/k8s/iac)
- **No telemetry** — zero data transmitted anywhere
- **No Nexora API** — fully self-contained open-source tool
- **Single binary** — CGO_ENABLED=0, cross-platform

## Installation

### Pre-built binary

```sh
# macOS/Linux
curl -sSfL https://github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/releases/latest/download/nexora_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv nexora /usr/local/bin/
```

### From source

```sh
git clone https://github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli.git
cd nexora-cli
make build
```

### Go install

```sh
go install github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli@latest
```

## Quick Start

```sh
# Scan GitHub Actions workflows
nexora scan k8s --path ./path/to/manifests

# Scan Kubernetes manifests
nexora scan k8s --path ./k8s/

# Scan IaC (Terraform, CloudFormation)
nexora scan iac --path ./terraform/

# Scan GitHub org via API (requires token)
nexora scan github --org my-org --token $GITHUB_TOKEN

# Output as SARIF
nexora scan k8s --path ./k8s/ --format sarif --output findings.sarif

# Generate evidence bundle
nexora report --input findings.json --bundle ./evidence-bundle/

# Verify bundle integrity
nexora verify bundle ./evidence-bundle/
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Scan complete, zero findings at or above `--severity` threshold |
| `1`  | Scan complete, findings exist at or above threshold |
| `2`  | Execution error (invalid flags, cannot read path, output write failure) |

## Detection Rules

### GitHub Actions

| Rule ID | Severity | Description |
|---------|----------|-------------|
| NXR-GH-001 | HIGH | Broad workflow-level write permissions without job scoping |
| NXR-GH-002 | HIGH | Action not pinned to commit SHA |
| NXR-GH-003 | CRITICAL | pull_request_target with PR-head checkout |
| NXR-GH-004 | CRITICAL | Hardcoded credential in workflow env |
| NXR-GH-005 | MEDIUM | Self-hosted runner without restriction labels |
| NXR-GH-006 | HIGH | Token exposure risk in pull_request_target |
| NXR-GH-007 | MEDIUM | Untrusted GitHub event body/title used in run step |
| NXR-GH-008 | MEDIUM | Scheduled workflow with write permissions |

### Kubernetes

| Rule ID | Severity | Description |
|---------|----------|-------------|
| NXR-K8S-001 | CRITICAL | ServiceAccount bound to cluster-admin |
| NXR-K8S-002 | INFO | ServiceAccount token automount not explicitly disabled |
| NXR-K8S-003 | LOW | Default ServiceAccount used in non-system namespace |
| NXR-K8S-004 | HIGH | Wildcard RBAC verbs on sensitive resources |
| NXR-K8S-005 | LOW | Projected ServiceAccountToken expirationSeconds too long |

### IaC

| Rule ID | Severity | Description |
|---------|----------|-------------|
| NXR-IAC-001 | CRITICAL | IAM wildcard action or service wildcard |
| NXR-IAC-002 | CRITICAL | Hardcoded credentials in IaC |
| NXR-IAC-003 | HIGH | IAM trust policy too broad — wildcard principal |
| NXR-IAC-004 | HIGH | Resource '*' with data-plane service wildcards |

## Output Formats

- `table` — human-readable tabular output (default)
- `json` — structured JSON with scan metadata
- `sarif` — SARIF 2.1.0 (GitHub Code Scanning compatible)
- `ocsf` — OCSF 1.1.0 Security Finding JSONL

## Evidence Bundles

```sh
nexora report --input findings.json --bundle ./bundle/
nexora verify bundle ./bundle/
```

Bundles contain `findings.json`, `findings.sarif`, `findings.ocsf.jsonl`, `scan-metadata.json`, and `manifest.json` with SHA-256 + SHA-512 per file and a root hash.

## GitHub Actions Integration

```yaml
- name: Scan workflows
  run: |
    nexora scan k8s --path ./k8s/ --format sarif --output nexora.sarif
    
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nexora.sarif
```

## Development

```sh
make test      # run tests with race detector
make lint      # golangci-lint
make security  # gosec + govulncheck
make build     # build binary
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
