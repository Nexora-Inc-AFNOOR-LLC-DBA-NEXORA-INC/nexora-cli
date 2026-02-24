#!/usr/bin/env bash
set -euo pipefail

# Verify a nexora-cli release artifact using cosign and checksums.txt
# Usage: ./scripts/verify-release.sh <version> <artifact>
# Example: ./scripts/verify-release.sh v0.1.0 nexora_0.1.0_linux_amd64.tar.gz

REPO="Nexora-NHI/nexora-cli"
VERSION="${1:-}"
ARTIFACT="${2:-}"

if [[ -z "$VERSION" || -z "$ARTIFACT" ]]; then
  echo "Usage: $0 <version> <artifact>" >&2
  exit 1
fi

BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

echo "==> Downloading checksums.txt..."
curl -sSfL "${BASE_URL}/checksums.txt" -o checksums.txt
curl -sSfL "${BASE_URL}/checksums.txt.sig" -o checksums.txt.sig
curl -sSfL "${BASE_URL}/checksums.txt.pem" -o checksums.txt.pem

echo "==> Verifying cosign signature on checksums.txt..."
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "^https://github.com/${REPO}/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt

echo "==> Verifying SHA-256 checksum for ${ARTIFACT}..."
grep "${ARTIFACT}" checksums.txt | sha256sum -c -

echo "==> Verification PASSED for ${ARTIFACT}"
