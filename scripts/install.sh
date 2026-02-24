#!/usr/bin/env bash
set -euo pipefail

REPO="Nexora-NHI/nexora-cli"
BINARY="nexora"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  arm64)   ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

VERSION="${VERSION:-$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')}"
if [[ -z "$VERSION" ]]; then
  echo "Could not determine latest version" >&2
  exit 1
fi

TARBALL="${BINARY}_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${TARBALL}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading nexora-cli ${VERSION} for ${OS}/${ARCH}..."
curl -sSfL "$URL" -o "${TMP}/${TARBALL}"

CHECKSUM_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"
curl -sSfL "$CHECKSUM_URL" -o "${TMP}/checksums.txt"

cd "$TMP"
grep "$TARBALL" checksums.txt | sha256sum -c -
tar xzf "$TARBALL"

install -m 0755 "$BINARY" "$INSTALL_DIR/$BINARY"
echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"
"${INSTALL_DIR}/${BINARY}" version
