# CI/CD Machine Identity Risk: Findings from 18 Open-Source Repos

February 2026 — Yasar Bin Gursain, Nexora

---

I built nexora-cli to scan GitHub Actions workflows, Kubernetes manifests, and Terraform configs for non-human identity risks. Before releasing it I ran it against 18 popular open-source projects to see what the real numbers look like. This is what came back.

No tokens were used. No private code was accessed. This is entirely based on reading public `.github/workflows/` files.

---

## The Numbers

| Finding | Repos affected | Rate |
|---|---|---|
| Workflow-level write permissions, no job scoping (NXR-GH-001) | 15/18 | 83% |
| Actions pinned to mutable tags like `@v3` (NXR-GH-002) | 9/18 | 50% |
| `pull_request_target` + PR head checkout (NXR-GH-003) | 1/18 | — |
| Token exposure via `pull_request_target` context (NXR-GH-006) | 7/18 | 39% |
| Scheduled workflow with write permissions (NXR-GH-008) | 1/18 | — |

**Total findings across 18 repos: 823**

Worst repos by finding count:

| Repo | Findings |
|---|---|
| grafana/grafana | 291 |
| facebook/react | 165 |
| vercel/next.js | 126 |
| fastapi/fastapi | 93 |
| django/django | 61 |
| microsoft/vscode | 53 |

Clean repos with zero findings: **cert-manager/cert-manager**, **open-policy-agent/opa**

---

## The Most Dangerous Pattern Found

One repo in the set triggered NXR-GH-003 — `pull_request_target` with checkout of the PR contributor's code. This is the most dangerous GitHub Actions misconfiguration that exists. I am disclosing that finding directly to the project before naming it here. This section will be updated once that process is complete.

Here is why the pattern matters regardless of which repo has it.

`pull_request_target` runs with write permissions to the base branch. It has to — it is designed for workflows that need to post comments, apply labels, update statuses on PRs from forks. The problem is when you combine it with a checkout of the PR contributor's code and then run anything from that working directory. That means external contributor code executes with write access to your main branch.

```yaml
# the dangerous pattern — simplified
on:
  pull_request_target:

jobs:
  analyze:
    steps:
      - uses: actions/checkout@<sha>
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      # anything that runs after this point executes contributor code
      # with the permissions of pull_request_target
```

An attacker submits a PR. The workflow triggers. Their code runs with write access. No approval required.

The safe version either avoids checking out PR code entirely, or splits the workflow into two — a `pull_request` workflow that checks out and runs the code (no write permissions), and a separate `pull_request_target` workflow that only uses outputs from the first, never touching the PR code directly.

---

## The Pattern Affecting 83% of Repos

The most widespread finding was workflow-level write permissions without job-level scoping. It looks like this:

```yaml
# common — permissions apply to every job in the workflow
on: push

permissions:
  contents: write
  packages: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: some-third-party-action@v2  # if this gets compromised,
                                           # it has write access to your repo
```

The correct version:

```yaml
# lock down at workflow level, each job gets only what it needs
on: push

permissions: {}

jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read   # test only needs to read
    steps:
      - uses: some-third-party-action@v2  # compromised action can only read

  release:
    permissions:
      contents: write  # only the release job gets write
      packages: write
```

One change. A compromised action in the test job cannot push to your repo.

facebook/react, microsoft/vscode, and grafana/grafana all had the broad permissions pattern. These are orgs with full-time security teams. This is not a small-project problem.

---

## Why cert-manager and OPA Were Clean

Both projects are maintained by people who work in security or cloud-native infrastructure professionally. The configs reflect active decisions — job-scoped permissions, pinned SHA references, no unnecessary token exposure.

The difference between a clean repo and a repo with 291 findings is not engineering skill. It is whether someone in the project actively owns CI security. Most projects do not have that person.

---

## The Self-Scan

I ran nexora-cli against nexora-cli's own workflows before writing this. Found 3 issues — all workflow-level permissions without job scoping. Fixed them in commit `ac50293` before publishing this. Pointing a scanner at other people's code without running it on your own first is not something I was willing to do.

---

## Repos Scanned

vercel/next.js, facebook/react, microsoft/vscode, django/django, fastapi/fastapi, prometheus/prometheus, grafana/grafana, hashicorp/terraform, cert-manager/cert-manager, argoproj/argo-cd, open-policy-agent/opa, aquasecurity/trivy, sigstore/cosign, goreleaser/goreleaser, helm/helm, crossplane/crossplane, fluxcd/flux2, tektoncd/pipeline

ansible/ansible and kubernetes/kubernetes were in the original list but their workflows live outside `.github/workflows/` in the sparse checkout — excluded from results.

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
