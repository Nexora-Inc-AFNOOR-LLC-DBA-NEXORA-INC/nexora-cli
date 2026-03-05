# CI/CD Machine Identity Risk: Findings from 14 More Open-Source Repos

March 2026 — Yasar Bin Gursain, Nexora

---

After publishing the February 2026 findings from 18 repos, I ran nexora-cli against 14 more popular open-source projects to see if the patterns held. Same methodology — no tokens, no private code, just reading public `.github/workflows/` files.

The results confirm what the first batch showed. The problems are widespread, predictable, and fixable.

---

## The Numbers

**Total findings across 14 repos: 267**

| Finding | Count | % of total |
|---|---|---|
| Actions pinned to mutable tags like `@v3` (NXR-GH-002) | 251 | 94% |
| Workflow-level write permissions, no job scoping (NXR-GH-001) | 13 | 5% |
| Token exposure via `pull_request_target` context (NXR-GH-006) | 3 | 1% |

All findings were severity 3 (medium-high). No critical findings (NXR-GH-003, NXR-GH-004) were detected in this batch.

---

## Repos by Finding Count

| Repo | Findings | Notes |
|---|---|---|
| actions/runner | 57 | GitHub's own runner has unpinned actions |
| golangci/golangci-lint | 41 | Popular Go linter |
| nektos/act | 39 | Local GitHub Actions runner |
| trufflesecurity/trufflehog | 35 | Secret scanner |
| github/super-linter | 31 | GitHub's official linter |
| aquasecurity/tfsec | 30 | Terraform security scanner |
| spf13/cobra | 11 | CLI framework used by kubectl, hugo |
| swaggo/swag | 8 | Swagger doc generator |
| bridgecrewio/checkov | 4 | IaC security scanner |
| envoyproxy/envoy | 4 | Cloud-native proxy |
| etcd-io/etcd | 3 | Distributed key-value store |
| anchore/grype | 2 | Vulnerability scanner |
| containerd/containerd | 2 | Container runtime |
| traefik/traefik | 0 | Clean |

---

## What Changed from Batch 1

In the first batch, 83% of repos had workflow-level write permissions without job scoping (NXR-GH-001). In this batch, only 13 findings across all repos — a much lower rate.

The dominant issue here is unpinned actions (NXR-GH-002) — 94% of all findings. This is the pattern where workflows reference third-party actions using mutable tags like `@v3` instead of pinned commit SHAs.

```yaml
# unpinned — tag can be moved to point at malicious code
- uses: actions/checkout@v4

# pinned — immutable reference
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

If the action maintainer's account gets compromised or the tag gets force-pushed, your workflow runs whatever the attacker wants. Pinning to a SHA prevents that.

---

## GitHub's Own Runner Has This Problem

`actions/runner` — the code that powers GitHub Actions runners — had 57 findings, all NXR-GH-002 (unpinned actions). This is the repo maintained by GitHub to run GitHub Actions.

That is not a criticism. It is a data point. If the team building the CI platform has unpinned actions in their own workflows, the problem is not lack of awareness. The problem is that pinning actions is tedious and most teams do not prioritize it until after an incident.

The same pattern showed up in `github/super-linter` (31 findings). These are official GitHub projects. The issue is structural, not individual.

---

## Security Tools Are Not Immune

Four of the repos in this batch are security scanning tools:
- trufflesecurity/trufflehog (35 findings)
- aquasecurity/tfsec (30 findings)
- bridgecrewio/checkov (4 findings)
- anchore/grype (2 findings)

Security tooling does not automatically mean secure CI/CD. The workflows that build and release these tools have the same risks as any other project.

---

## The One Clean Repo

`traefik/traefik` had zero findings. This is a cloud-native reverse proxy with 50,000+ stars. The workflows use pinned SHAs, job-scoped permissions, and no risky patterns.

Like cert-manager and OPA from the first batch, this is not luck. Someone on the Traefik team actively owns CI security. The difference between 0 findings and 57 findings is not engineering capability — it is whether CI security is treated as a maintained system or an afterthought.

---

## Comparing Batch 1 and Batch 2

| Metric | Batch 1 (18 repos) | Batch 2 (14 repos) |
|---|---|---|
| Total findings | 823 | 267 |
| Avg findings per repo | 46 | 19 |
| Repos with 0 findings | 2 (11%) | 1 (7%) |
| Most common issue | NXR-GH-001 (83%) | NXR-GH-002 (94%) |

Batch 2 had fewer findings per repo on average, but the pattern distribution was different. Batch 1 was dominated by overly broad permissions. Batch 2 was dominated by unpinned actions.

Both batches confirm the same underlying issue: most projects do not treat CI/CD configuration as security-critical infrastructure. The defaults are insecure and most teams do not change them.

---

## What This Means

If you run GitHub Actions, you almost certainly have at least one of these issues:
1. Workflow-level write permissions that apply to all jobs
2. Third-party actions pinned to mutable tags instead of commit SHAs
3. Token exposure via `pull_request_target` or other contexts

These are not theoretical. They are present in repos maintained by GitHub, major security vendors, and CNCF projects.

The fix is not complicated. It is tedious. Pin actions to SHAs. Scope permissions to individual jobs. Do not check out PR code in `pull_request_target` workflows. Most teams do not do this because it is not enforced and the risk is invisible until it is not.

---

## Repos Scanned

traefik/traefik, envoyproxy/envoy, containerd/containerd, etcd-io/etcd, anchore/grype, aquasecurity/tfsec, bridgecrewio/checkov, trufflesecurity/trufflehog, actions/runner, nektos/act, github/super-linter, golangci/golangci-lint, swaggo/swag, spf13/cobra

istio/istio was in the original list but workflows were not in `.github/workflows/` — excluded from results.

---

## Checking Your Own Repo

```bash
# install
curl -sSfL https://github.com/Nexora-NHI/nexora-cli/releases/latest/download/nexora_$(uname -s)_$(uname -m).tar.gz | tar xz
sudo mv nexora /usr/local/bin/

# scan your workflows
nexora scan workflows --path ./.github/workflows/

# get SARIF output for GitHub Code Scanning
nexora scan workflows --path ./.github/workflows/ --format sarif --output findings.sarif
```

Read-only. No telemetry. No API calls. Works offline.

For the full list of rules and what each one catches, see the [README](../../README.md).

---

## About nexora-cli

Open-source CLI built by [Nexora](https://nexora.inc). Apache 2.0 licensed. The CLI is the detection layer for a commercial platform that adds autonomous remediation and post-quantum cryptography for enterprise machine identity management. The CLI will always be free.

[GitHub](https://github.com/Nexora-NHI/nexora-cli)
