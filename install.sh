#!/usr/bin/env sh
# SCP2P installer for Linux and macOS.
#
# Installs scp2p-relay (default) or scp2p-cli from pre-built GitHub releases.
#
# Usage:
#   Install relay (default):
#     curl -sSfL https://github.com/techartdev/scp2p/raw/main/install.sh | sh
#
#   Install CLI:
#     curl -sSfL https://github.com/techartdev/scp2p/raw/main/install.sh | sh -s -- --tool cli
#
#   Pin a version:
#     curl -sSfL https://github.com/techartdev/scp2p/raw/main/install.sh | sh -s -- --version 0.1.0
#
#   Custom install dir:
#     curl -sSfL https://github.com/techartdev/scp2p/raw/main/install.sh | sh -s -- --dir ~/bin
set -e

REPO="techartdev/scp2p"
INSTALL_DIR="${SCP2P_INSTALL_DIR:-/usr/local/bin}"

# ── Argument parsing ────────────────────────────────────────────────────────
TOOL="relay"    # relay | cli
VERSION=""

while [ $# -gt 0 ]; do
  case $1 in
    --tool)    TOOL="$2";    shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --dir)     INSTALL_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: install.sh [--tool relay|cli] [--version <ver>] [--dir <dir>]"
      echo "  --tool      Which tool to install: relay (default) or cli"
      echo "  --version   Pin a specific release tag (default: latest)"
      echo "  --dir       Installation directory (default: /usr/local/bin)"
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# Resolve binary name and release tag prefix from tool selection.
case "$TOOL" in
  relay)
    BIN="scp2p-relay"
    ASSET_PREFIX="scp2p-relay"
    TAG_FILTER="relay-v"          # relay releases are tagged relay-vX.Y.Z
    ;;
  cli)
    BIN="scp2p"
    ASSET_PREFIX="scp2p"          # asset: scp2p-linux-x86_64
    TAG_FILTER="v"                # core releases are tagged vX.Y.Z
    ;;
  *)
    echo "Unknown tool: '$TOOL'. Use 'relay' or 'cli'." >&2
    exit 1 ;;
esac

# ── Platform detection ────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)   PLATFORM="linux" ;;
  Darwin)  PLATFORM="macos" ;;
  *)       echo "Unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
  x86_64|amd64)   ARCH_TAG="x86_64" ;;
  aarch64|arm64)  ARCH_TAG="aarch64" ;;
  *)               echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

ASSET="${ASSET_PREFIX}-${PLATFORM}-${ARCH_TAG}"

# ── Resolve version ─────────────────────────────────────────────────────────
if [ -z "$VERSION" ]; then
  echo "Fetching latest ${BIN} release..."
  # Fetch all releases and pick the first tag matching this tool's prefix.
  API_RESP="$(curl -sSfL "https://api.github.com/repos/${REPO}/releases" 2>/dev/null \
    || wget -qO- "https://api.github.com/repos/${REPO}/releases" 2>/dev/null)"
  VERSION="$(printf '%s' "$API_RESP" \
    | grep '"tag_name"' \
    | grep "\"${TAG_FILTER}" \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"
  if [ -z "$VERSION" ]; then
    echo "Could not determine latest version. Use --version to specify one." >&2
    exit 1
  fi
fi

printf 'Installing %s %s  (%s/%s)\n' "$BIN" "$VERSION" "$PLATFORM" "$ARCH_TAG"

# ── Download ──────────────────────────────────────────────────────
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
TMP="$(mktemp)"

if command -v curl >/dev/null 2>&1; then
  curl -sSfL "$URL" -o "$TMP"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP" "$URL"
else
  echo "Neither curl nor wget found. Install one of them and retry." >&2
  rm -f "$TMP"
  exit 1
fi

chmod +x "$TMP"

# ── Install ───────────────────────────────────────────────────────
DEST="${INSTALL_DIR}/${BIN}"

# Try to write to INSTALL_DIR; fall back to ~/.local/bin when unprivileged.
if [ ! -w "$INSTALL_DIR" ] 2>/dev/null; then
  FALLBACK="$HOME/.local/bin"
  echo "No write permission to ${INSTALL_DIR}; installing to ${FALLBACK} instead."
  echo "  (re-run with sudo if you want a system-wide install)"
  mkdir -p "$FALLBACK"
  DEST="${FALLBACK}/${BIN}"
  # Warn if not in PATH
  case ":$PATH:" in
    *":$FALLBACK:"*) ;;
    *) echo "  NOTE: add ${FALLBACK} to your PATH:  export PATH=\"\$PATH:${FALLBACK}\"" ;;
  esac
fi

mv "$TMP" "$DEST"
echo "Installed → ${DEST}"
echo ""
echo "  Verify:  ${BIN} --version"
echo "  Start:   ${BIN}"
echo "  Docs:    https://github.com/${REPO}/blob/main/crates/${ASSET_PREFIX}/README.md"
