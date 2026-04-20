#!/usr/bin/env bash
#
# Install atem — Agora's CLI for real-time communication.
#
# Quick install (works in regions where GitHub is not available):
#   curl -fsSL https://dl.agora.build/atem/install.sh | bash
#
# Options (via env vars):
#   ATEM_VERSION=0.4.91   Pin a specific version (default: latest)
#   ATEM_BASE_URL=...     Override download base URL
#   ATEM_INSTALL_DIR=...  Override install directory
#
set -euo pipefail

BASE_URL="${ATEM_BASE_URL:-https://dl.agora.build/atem/releases}"

# ── Helpers ──────────────────────────────────────────────────────────

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "  $*"; }

# ── Detect platform ──────────────────────────────────────────────────

detect_platform() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"

  case "$os" in
    linux)  os="linux" ;;
    darwin) os="darwin" ;;
    *)      die "Unsupported OS: $os (supported: linux, darwin)" ;;
  esac

  case "$arch" in
    x86_64|amd64)   arch="x86_64" ;;
    aarch64|arm64)  arch="aarch64" ;;
    *)              die "Unsupported architecture: $arch (supported: x86_64, aarch64)" ;;
  esac

  echo "${os}-${arch}"
}

# ── Resolve version ─────────────────────────────────────────────────

resolve_version() {
  if [ -n "${ATEM_VERSION:-}" ]; then
    echo "$ATEM_VERSION"
    return
  fi

  local url="${BASE_URL}/latest"
  local version
  version="$(curl -fsSL "$url" 2>/dev/null)" \
    || die "Failed to fetch latest version from $url"
  version="$(echo "$version" | tr -d '[:space:]')"
  [ -n "$version" ] || die "Empty version returned from $url"
  echo "$version"
}

# ── Pick install directory ───────────────────────────────────────────

pick_install_dir() {
  if [ -n "${ATEM_INSTALL_DIR:-}" ]; then
    echo "$ATEM_INSTALL_DIR"
    return
  fi

  if [ -w "/usr/local/bin" ]; then
    echo "/usr/local/bin"
  else
    local dir="${HOME}/.local/bin"
    mkdir -p "$dir"
    echo "$dir"
  fi
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
  echo "Installing atem..."

  local platform version install_dir
  platform="$(detect_platform)"
  version="$(resolve_version)"
  install_dir="$(pick_install_dir)"

  local archive="atem-v${version}-${platform}.tar.gz"
  local url="${BASE_URL}/v${version}/${archive}"

  info "Version:  ${version}"
  info "Platform: ${platform}"
  info "From:     ${url}"
  info "To:       ${install_dir}/atem"

  # Download + extract to temp dir
  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  curl -fSL --progress-bar "$url" -o "${tmpdir}/${archive}" \
    || die "Download failed: ${url}"

  tar -xzf "${tmpdir}/${archive}" -C "$tmpdir" \
    || die "Failed to extract ${archive}"

  # Install
  chmod +x "${tmpdir}/atem"
  mv "${tmpdir}/atem" "${install_dir}/atem" \
    || die "Failed to install to ${install_dir}/atem (try: sudo or set ATEM_INSTALL_DIR)"

  # Verify
  if command -v atem >/dev/null 2>&1; then
    local installed_version
    installed_version="$(atem --version 2>/dev/null | head -1)"
    echo ""
    echo "Installed: ${installed_version}"
  else
    echo ""
    echo "Installed to ${install_dir}/atem"
    # Check if install_dir is in PATH
    case ":${PATH}:" in
      *":${install_dir}:"*) ;;
      *)
        echo ""
        echo "Add to your PATH:"
        echo "  export PATH=\"${install_dir}:\$PATH\""
        echo ""
        echo "Or add to your shell profile (~/.bashrc, ~/.zshrc):"
        echo "  echo 'export PATH=\"${install_dir}:\$PATH\"' >> ~/.bashrc"
        ;;
    esac
  fi
}

main "$@"
