# Contributing to nexora-cli

## Getting Started

```sh
git clone https://github.com/Nexora-Inc-AFNOOR-LLC-DBA-NEXORA-INC/nexora-cli.git
cd nexora-cli
go mod tidy
make test
```

## Development Requirements

- Go 1.22+
- golangci-lint v1.57.2
- gosec v2.19.0

## Pull Request Guidelines

1. All new detection rules must include unit tests in `rules_test.go`
2. All new rules must have fixtures in `fixtures/vulnerable/` and `fixtures/clean/`
3. Tests must pass with `-race`: `make test`
4. Lint must pass: `make lint`
5. Security scan must pass: `make security`
6. No network calls in file-based scanners
7. No `os/exec` in any scanner
8. No `init()` that mutates global state

## Adding a New Rule

1. Add the rule function to the appropriate `rules.go` file
2. Add the rule check to `runAllRules()` in `scanner.go`
3. Add tests to `rules_test.go`
4. Add a vulnerable fixture with header comments
5. Verify the clean fixture produces zero findings

## SaaS Boundary

This is an open-source tool. Do not include:
- Nexora internal API endpoints
- SaaS engine logic
- ML/behavioral detection
- Telemetry or analytics

## Code of Conduct

Be respectful and constructive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) if present.
