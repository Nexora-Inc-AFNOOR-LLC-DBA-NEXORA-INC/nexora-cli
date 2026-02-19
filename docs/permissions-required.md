# Permissions Required

## File-Based Scans (workflows, k8s, iac)

**No special permissions required.**

nexora-cli only reads files from the local filesystem. It requires:
- Read access to the files/directories being scanned

No write operations are performed. No network access is made.

## GitHub API Scan (`nexora scan github`)

Requires a GitHub token with:
- `repo` scope — for private repositories
- `public_repo` scope — for public repositories only

The token is used only to:
1. List repositories in an organisation (if `--org` is used)
2. Read `.github/workflows/` directory contents
3. Read individual workflow file contents

The token is **never logged**, **never stored**, and **never transmitted** to any Nexora system.

## CI/CD

When running in GitHub Actions, use `${{ secrets.GITHUB_TOKEN }}` with minimal permissions:

```yaml
permissions:
  contents: read
```

For org-wide scanning, use a fine-grained PAT scoped to the target repositories.
