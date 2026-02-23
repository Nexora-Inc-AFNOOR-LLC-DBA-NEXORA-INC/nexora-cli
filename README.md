# nexora-cli

![demo](demo.gif)

Open-source CLI that finds Non-Human Identity (NHI) risks in GitHub Actions workflows, Kubernetes manifests, and Terraform/IaC files — before they become incidents.

Built by [Nexora](https://nexora.inc). MIT licensed. No telemetry. No SaaS. Runs entirely on your machine.

---

## Why this exists

Most breaches involving service accounts, CI tokens, and machine credentials trace back to the same handful of misconfigurations — unpinned actions, cluster-admin bindings, hardcoded secrets, wildcard IAM policies. These patterns are detectable statically. nexora-cli does exactly that.

It does not call home. It does not require an account. It reads files and tells you what it finds.

---

## Install

**macOS / Linux — pre-built binary**

```sh
curl -sSfL https://github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/releases/latest/download/nexora_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv nexora /usr/local/bin/
nexora version
```

**Go install**

```sh
go install github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli@latest
```

**Build from source**

```sh
git clone https://github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli.git
cd nexora-cli
make build
```

---

## Usage

```sh
# Scan GitHub Actions workflows in your repo (no token needed)
nexora scan workflows --path ./.github/workflows/

# Scan Kubernetes manifests
nexora scan k8s --path ./k8s/

# Scan Terraform / IaC files
nexora scan iac --path ./terraform/

# Scan a GitHub org via API (token required)
export GITHUB_TOKEN=ghp_...
nexora scan github --org my-org

# Get SARIF output for GitHub Code Scanning
nexora scan k8s --path ./k8s/ --format sarif --output findings.sarif

# Generate a tamper-evident evidence bundle
nexora scan k8s --path ./k8s/ --format json --output findings.json
nexora report --input findings.json --bundle ./bundle/
nexora verify bundle ./bundle/
```

---

## Exit codes

| Code | What it means |
|------|---------------|
| `0` | Scan finished, nothing found at or above the severity threshold |
| `1` | Scan finished, findings exist at or above the threshold |
| `2` | Something went wrong — bad flags, unreadable path, write failure |

CI pipelines can use exit code `1` to fail a build on findings.

---

## What it detects

### GitHub Actions — 8 rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| NXR-GH-001 | HIGH | Workflow-level write permissions with no job-level scoping |
| NXR-GH-002 | HIGH | Action pinned to a tag or branch instead of a commit SHA |
| NXR-GH-003 | CRITICAL | `pull_request_target` with checkout of PR head code |
| NXR-GH-004 | CRITICAL | Hardcoded credential in `env`, `with`, or `run` blocks |
| NXR-GH-005 | MEDIUM | Self-hosted runner with no label restrictions |
| NXR-GH-006 | HIGH | Token exposed via `pull_request_target` context |
| NXR-GH-007 | MEDIUM | Untrusted PR title or body used directly in a `run` step |
| NXR-GH-008 | MEDIUM | Scheduled workflow with write permissions |

### Kubernetes — 5 rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| NXR-K8S-001 | CRITICAL | ServiceAccount bound to `cluster-admin` |
| NXR-K8S-002 | LOW | `automountServiceAccountToken` not explicitly disabled |
| NXR-K8S-003 | LOW | Default ServiceAccount used in a non-system namespace |
| NXR-K8S-004 | HIGH | Wildcard verbs on sensitive RBAC resources |
| NXR-K8S-005 | LOW | Projected ServiceAccountToken with a long expiry |

### IaC / Terraform — 4 rules

| Rule | Severity | What it catches |
|------|----------|-----------------|
| NXR-IAC-001 | CRITICAL | IAM wildcard action (`"*"`) — single line or multi-line block |
| NXR-IAC-002 | CRITICAL | Hardcoded AWS credentials in config files |
| NXR-IAC-003 | HIGH | IAM trust policy with a wildcard principal |
| NXR-IAC-004 | HIGH | Resource `"*"` combined with data-plane service wildcards |

---

## Output formats

| Flag | Format | Use case |
|------|--------|----------|
| `--format table` | Terminal table with color | Default, local review |
| `--format json` | Structured JSON | Pipelines, custom tooling |
| `--format sarif` | SARIF 2.1.0 | GitHub Code Scanning, VS Code |
| `--format ocsf` | OCSF 1.1.0 JSONL | AWS Security Lake, Splunk |

---

## Evidence bundles

If you need to hand findings to a compliance team or auditor, generate a bundle:

```sh
nexora report --input findings.json --bundle ./bundle/
nexora verify bundle ./bundle/
```

The bundle contains `findings.json`, `findings.sarif`, `findings.ocsf.jsonl`, `scan-metadata.json`, and a `manifest.json` with SHA-256 and SHA-512 checksums per file plus a root hash. The verify command checks all of them.

---

## Drop it into GitHub Actions

```yaml
jobs:
  nhi-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6.0.2

      - name: Install nexora-cli
        run: |
          curl -sSfL https://github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli/releases/latest/download/nexora_Linux_x86_64.tar.gz | tar xz
          sudo mv nexora /usr/local/bin/

      - name: Scan workflows
        run: nexora scan workflows --path ./.github/workflows/ --format sarif --output workflows.sarif

      - name: Scan Kubernetes
        run: nexora scan k8s --path ./k8s/ --format sarif --output k8s.sarif

      - name: Upload to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@60168efe1c415ce0f5521ea06d5c2062adbeed1b # v3
        with:
          sarif_file: workflows.sarif
```

Findings show up as PR annotations in GitHub Code Scanning automatically.

---

## Research

[CI/CD Machine Identity Risk: Findings from 18 Open-Source Repos →](docs/research/ci-cd-nhi-scan-2026.md)

---

## Contributing

```sh
make test      # tests with race detector
make lint      # golangci-lint
make security  # gosec + govulncheck
make build     # build binary
```

All new rules need a unit test and fixtures in `fixtures/vulnerable/` and `fixtures/clean/`. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
