# Getting Started with nexora-cli

## Prerequisites

- Go 1.22+ (for building from source)
- Or download a pre-built binary from [Releases](https://github.com/Nexora-NHI/nexora-cli/releases)

## Install

```sh
# From source
git clone https://github.com/Nexora-NHI/nexora-cli.git
cd nexora-cli
make build
sudo mv nexora /usr/local/bin/

# Verify
nexora version
```

## First Scan in 10 Minutes

### Scan GitHub Actions workflows (local, no token required)

```sh
nexora scan workflows --path ./.github/workflows/
```

### Scan Kubernetes manifests

```sh
nexora scan k8s --path ./k8s/
```

### Scan Terraform

```sh
nexora scan iac --path ./terraform/
```

### Filter by severity

```sh
nexora scan k8s --path ./k8s/ --severity high
```

### Output as JSON

```sh
nexora scan k8s --path ./k8s/ --format json --output findings.json
```

### Generate evidence bundle

```sh
nexora report --input findings.json --bundle ./bundle/
nexora verify bundle ./bundle/
```

## GitHub Actions Integration

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
          curl -sSfL https://github.com/Nexora-NHI/nexora-cli/releases/latest/download/nexora_Linux_x86_64.tar.gz | tar xz
          sudo mv nexora /usr/local/bin/
      - name: Scan workflows
        run: nexora scan workflows --path ./.github/workflows/ --format sarif --output nexora.sarif
      - name: Scan Kubernetes
        run: nexora scan k8s --path ./k8s/ --format sarif --output k8s.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: nexora.sarif
```
