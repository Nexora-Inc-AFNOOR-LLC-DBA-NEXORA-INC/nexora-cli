# nexora-cli

**The only CLI that audits Non-Human Identity *lifecycle*, not just configuration.**

[![CI](https://github.com/Nexora-NHI/nexora-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/Nexora-NHI/nexora-cli/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/Nexora-NHI/nexora-cli)](https://goreportcard.com/report/github.com/Nexora-NHI/nexora-cli)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Nexora-NHI/nexora-cli)](https://github.com/Nexora-NHI/nexora-cli/releases)

---

## What Makes This Different

Every scanner finds misconfigurations. Trivy, Checkov, Semgrep—they all read YAML files and flag issues.

**nexora-cli does three things they can't:**

| Capability | File Scanners | nexora-cli |
|------------|---------------|------------|
| Find misconfigured YAML | ✅ | ✅ |
| Check credential age | ❌ | ✅ |
| Check when credential was last used | ❌ | ✅ |
| Check rotation status | ❌ | ✅ |
| Map blast radius (what can X reach?) | ❌ | ✅ |
| Trace identity relationships | ❌ | ✅ |

**File scanners read files. nexora-cli audits identities.**

---

## Quick Start

```bash
# Install
go install github.com/Nexora-NHI/nexora-cli@latest

# Or download binary
curl -sSL https://github.com/Nexora-NHI/nexora-cli/releases/latest/download/nexora-linux-amd64 -o nexora
chmod +x nexora
```

---

## Commands

### 1. Scan (Static Analysis)

Find misconfigurations in workflow files, K8s manifests, Terraform.

```bash
# Local files
nexora scan workflows --path ./.github/workflows/
nexora scan k8s --path ./manifests/
nexora scan iac --path ./terraform/

# Via GitHub API
nexora scan github --org my-org
```

**Output:**
```
NXR-GH-001 | HIGH | Broad workflow-level write permissions
  File: .github/workflows/ci.yml:5
  
  Workflow has write-all permissions. Scope to job level with minimal permissions.
  
NXR-GH-002 | HIGH | Action not pinned to commit SHA  
  File: .github/workflows/ci.yml:15
  Evidence: uses: actions/checkout@v4
  
  Pin to SHA: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

### 2. Audit (API-Powered Lifecycle Analysis)

**This is unique.** No file scanner can do this.

```bash
nexora audit github --org my-org
```

**Output:**
```
═══════════════════════════════════════════════════════════
CREDENTIAL AUDIT: my-org
═══════════════════════════════════════════════════════════

Total Credentials: 47

By Risk Level:
  🔴 CRITICAL: 3
  🟠 HIGH:     8
  🟡 MEDIUM:   12
  🟢 LOW:      24

Issues Detected:
  ⏰ Stale (>90 days old):        15
  💤 Dormant (unused >30 days):   12
  🔄 Never rotated:               23

═══════════════════════════════════════════════════════════
CREDENTIALS REQUIRING IMMEDIATE ATTENTION
═══════════════════════════════════════════════════════════

🔴 deploy-key-production [CRITICAL]
   Type: deploy_key | Age: 847 days
   Scope: contents:write
   Issues:
     • Very old: 847 days (max recommended: 90)
     • Never rotated since creation

🔴 legacy-ci-bot [CRITICAL]
   Type: github_app | Age: 412 days
   Scope: admin:write, contents:write, secrets:write
   Issues:
     • Very old: 412 days
     • Has access to ALL repositories
```

### 3. Map (Identity Relationship & Blast Radius)

**This is unique.** Shows what an attacker can reach if an identity is compromised.

```bash
nexora map --org my-org --blast-from "ci-workflow"
```

**Output:**
```
🎯 BLAST RADIUS ANALYSIS: ci-workflow
══════════════════════════════════════════════════════════

Risk Score: 7.2/10
Reachable Nodes: 12
Max Depth: 4 hops
Critical/High Resources Reachable: 3

Shortest Path to Critical Resource:
└─ ci-workflow (github_workflow)
  └─ AWS_SECRET_KEY (github_secret) ⚠️ HIGH
    └─ arn:aws:iam::123:role/deploy (aws_iam_role)
      └─ prod-database-bucket (aws_resource) ⚠️ CRITICAL

Reachable Resources by Risk:

  [CRITICAL] (1)
    • prod-database-bucket (depth: 4)

  [HIGH] (2)
    • AWS_SECRET_KEY (depth: 1)
    • deploy-role (depth: 2)
```

**Export for visualization:**
```bash
nexora map --org my-org --format dot --output graph.dot
dot -Tpng graph.dot -o identity-map.png
```

---

## What It Detects

### GitHub Actions
| Rule | Description |
|------|-------------|
| NXR-GH-001 | Workflow-level write permissions (should be job-scoped) |
| NXR-GH-002 | Action not pinned to commit SHA (supply chain risk) |
| NXR-GH-003 | pull_request_target with PR head checkout (code injection) |
| NXR-GH-004 | Hardcoded credentials in workflow |
| NXR-GH-005 | Self-hosted runner without restrictions |
| NXR-GH-006 | Token exposed via pull_request_target |
| NXR-GH-007 | Untrusted input in run step |
| NXR-GH-008 | Scheduled workflow with write permissions |

### Kubernetes
| Rule | Description |
|------|-------------|
| NXR-K8S-001 | ServiceAccount bound to cluster-admin |
| NXR-K8S-002 | automountServiceAccountToken not disabled |
| NXR-K8S-003 | Default ServiceAccount used |
| NXR-K8S-004 | Wildcard RBAC verbs |
| NXR-K8S-005 | Projected token with long expiry |

### Infrastructure as Code
| Rule | Description |
|------|-------------|
| NXR-IAC-001 | IAM policy with wildcard actions |
| NXR-IAC-002 | Hardcoded AWS credentials |
| NXR-IAC-003 | IAM trust policy too broad |
| NXR-IAC-004 | Resource wildcard with broad actions |

### Lifecycle (API-Powered)
| Check | What It Detects |
|-------|-----------------|  
| Age | Credentials older than 90 days |
| Rotation | Never rotated or overdue for rotation |
| Dormancy | Credentials not used in 30+ days |
| Expiration | Expired or expiring soon |
| Scope creep | Permissions broader than needed |

---

## Output Formats

```bash
# Terminal (default)
nexora scan workflows --path ./

# JSON
nexora scan workflows --path ./ --format json

# SARIF (for GitHub Code Scanning)
nexora scan workflows --path ./ --format sarif --output results.sarif

# OCSF (for SIEM integration)
nexora scan workflows --path ./ --format ocsf
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Install nexora-cli
  run: |
    bash -c "$(curl -sSfL https://raw.githubusercontent.com/Nexora-NHI/nexora-cli/main/scripts/install.sh)"

- name: Scan NHI risks
  run: nexora scan workflows --path .github/workflows/ --format sarif --output nexora.sarif

- name: Upload to Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nexora.sarif
```

### GitLab CI

```yaml
nhi-scan:
  image: golang:1.21
  script:
    - go install github.com/Nexora-NHI/nexora-cli@latest
    - nexora scan workflows --path .gitlab-ci.yml --format sarif --output nexora.sarif
  artifacts:
    reports:
      sast: nexora.sarif
```

---

## Research

We scanned 32 popular open-source repos (18 in batch 1, 14 in batch 2). Real findings:

**Batch 1 (18 repos):** 823 total findings
- 83% had workflow-level write permissions (should be job-scoped)
- 50% had unpinned actions
- Worst offenders: grafana/grafana (291), facebook/react (165), vercel/next.js (126)
- Clean repos: cert-manager, OPA

**Batch 2 (14 repos):** 267 total findings
- 94% unpinned actions
- 5% workflow-level permissions
- Worst offenders: actions/runner (57), golangci-lint (41), nektos/act (39)
- Clean repo: traefik

Security tools scanned:
- trufflesecurity/trufflehog: 35 findings
- aquasecurity/tfsec: 30 findings
- github/super-linter: 31 findings

[Batch 1 research →](docs/research/ci-cd-nhi-scan-2026.md) | [Batch 2 research →](docs/research/ci-cd-nhi-scan-2026-batch2.md)

---

## Privacy

- **No telemetry.** We don't collect usage data.
- **Offline-first.** Static scanning works without network.
- **API calls are explicit.** `audit` and `map` commands clearly require API access.
- **Your data stays local.** No cloud upload.

---

## Contributing

Issues and PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0

---

## Why We Built This

The tj-actions incident (March 2025) compromised 23,000 repos because workflows used `@v39` instead of pinning to SHA.

But the bigger problem: those repos had service accounts, deploy keys, and API tokens that were never audited. Created years ago. Never rotated. No one knew what they could access.

File scanners catch one part of this. nexora-cli catches the rest.

---

**Star us if this is useful:** [github.com/Nexora-NHI/nexora-cli](https://github.com/Nexora-NHI/nexora-cli)
