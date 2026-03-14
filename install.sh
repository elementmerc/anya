#!/usr/bin/env bash
# Anya — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/master/install.sh | bash
#
# Platform support:
#   CLI  : macOS (x86_64, arm64), Linux (x86_64, arm64), Windows (via WSL/Git-Bash)
#   GUI  : macOS (.dmg), Linux (.AppImage / .deb), Windows (.msi)
#
# Environment variables:
#   ANYA_VERSION   — install a specific tag, e.g. ANYA_VERSION=v0.4.0
#   ANYA_NO_COLOR  — set to any non-empty value to disable colour output
#   ANYA_INSTALL_DIR — override CLI install directory (default: $HOME/.local/bin)

set -uo pipefail

# ─── Colours ─────────────────────────────────────────────────────────────────

if [ -z "${ANYA_NO_COLOR:-}" ] && [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# ─── Helpers ─────────────────────────────────────────────────────────────────

info()    { printf "${CYAN}  →${RESET} %s\n" "$*"; }
success() { printf "${GREEN}  ✓${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}  ⚠${RESET} %s\n" "$*"; }
error()   { printf "${RED}  ✗${RESET} %s\n" "$*" >&2; }
header()  { printf "\n${BOLD}%s${RESET}\n" "$*"; }

die() {
  error "$*"
  exit 1
}

# Minimal spinner that works without background jobs
spinner_start() {
  _SPINNER_MSG="$*"
  _SPINNER_FRAMES=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  _SPINNER_IDX=0
}
spinner_tick() {
  printf "\r${CYAN}  %s${RESET}  %s " "${_SPINNER_FRAMES[$_SPINNER_IDX]}" "${_SPINNER_MSG}"
  _SPINNER_IDX=$(( (_SPINNER_IDX + 1) % ${#_SPINNER_FRAMES[@]} ))
}
spinner_stop() {
  printf "\r\033[2K"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command '$1' not found. Please install it and retry."
}

# ─── Platform detection ───────────────────────────────────────────────────────

detect_platform() {
  _OS="$(uname -s)"
  _ARCH="$(uname -m)"

  case "$_OS" in
    Linux)
      OS="linux"
      case "$_ARCH" in
        x86_64)  ARCH="x86_64"  ;;
        aarch64) ARCH="aarch64" ;;
        *)       die "Unsupported Linux architecture: $_ARCH" ;;
      esac
      ;;
    Darwin)
      OS="macos"
      # Both x86_64 and arm64 covered by the universal binary
      ARCH="universal"
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      OS="windows"
      ARCH="x86_64"
      ;;
    *)
      die "Unsupported OS: $_OS"
      ;;
  esac
}

# ─── Version resolution ───────────────────────────────────────────────────────

resolve_version() {
  if [ -n "${ANYA_VERSION:-}" ]; then
    VERSION="$ANYA_VERSION"
    return
  fi

  info "Fetching latest release version…"
  require_cmd curl

  VERSION="$(curl -fsSL "https://api.github.com/repos/elementmerc/anya/releases/latest" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')"

  [ -n "$VERSION" ] || die "Could not determine latest release. Set ANYA_VERSION manually."
}

# ─── Download helper ──────────────────────────────────────────────────────────

download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --tries=3 -O "$dest" "$url"
  else
    die "Neither curl nor wget found. Install one and retry."
  fi
}

# ─── CLI install ──────────────────────────────────────────────────────────────

install_cli() {
  header "Installing Anya CLI"

  local INSTALL_DIR="${ANYA_INSTALL_DIR:-$HOME/.local/bin}"
  local BINARY_NAME="anya"

  # Determine asset name
  local ASSET
  case "$OS" in
    linux)
      case "$ARCH" in
        x86_64)  ASSET="anya-${VERSION}-x86_64-unknown-linux-musl.tar.gz" ;;
        aarch64) ASSET="anya-${VERSION}-aarch64-unknown-linux-musl.tar.gz" ;;
      esac
      ;;
    macos)
      ASSET="anya-${VERSION}-universal-apple-darwin.tar.gz"
      ;;
    windows)
      ASSET="anya-${VERSION}-x86_64-pc-windows-msvc.zip"
      BINARY_NAME="anya.exe"
      ;;
  esac

  local DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
  local TMP_DIR
  TMP_DIR="$(mktemp -d)"
  local TMP_FILE="$TMP_DIR/$ASSET"

  info "Downloading $ASSET…"
  spinner_start "Downloading"

  if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
    spinner_stop
    warn "Pre-built binary not found for $OS/$ARCH — falling back to cargo install"
    install_cli_cargo
    rm -rf "$TMP_DIR"
    return
  fi
  spinner_stop

  # Extract
  mkdir -p "$INSTALL_DIR"
  case "$ASSET" in
    *.tar.gz)
      require_cmd tar
      tar -xzf "$TMP_FILE" -C "$TMP_DIR"
      ;;
    *.zip)
      require_cmd unzip
      unzip -q "$TMP_FILE" -d "$TMP_DIR"
      ;;
  esac

  local EXTRACTED_BINARY
  EXTRACTED_BINARY="$(find "$TMP_DIR" -name "$BINARY_NAME" -not -name "*.tar.gz" | head -1)"
  [ -n "$EXTRACTED_BINARY" ] || die "Could not find binary '$BINARY_NAME' in the downloaded archive."

  install -m 755 "$EXTRACTED_BINARY" "$INSTALL_DIR/$BINARY_NAME"
  rm -rf "$TMP_DIR"

  success "CLI installed to $INSTALL_DIR/$BINARY_NAME"
  ensure_in_path "$INSTALL_DIR"
}

install_cli_cargo() {
  info "Installing via cargo (this compiles from source — may take a few minutes)…"
  require_cmd cargo
  cargo install anya-security-core --locked || die "cargo install failed"
  success "CLI installed via cargo"
}

ensure_in_path() {
  local dir="$1"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *)
      warn "$dir is not in your PATH."
      warn "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
      printf "\n    export PATH=\"%s:\$PATH\"\n\n" "$dir"
      ;;
  esac
}

# ─── GUI install ──────────────────────────────────────────────────────────────

install_gui() {
  header "Installing Anya GUI"

  local ASSET DOWNLOAD_URL TMP_DIR TMP_FILE

  case "$OS" in
    macos)
      ASSET="Anya_${VERSION#v}_universal.dmg"
      DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
      TMP_DIR="$(mktemp -d)"
      TMP_FILE="$TMP_DIR/$ASSET"

      info "Downloading $ASSET…"
      spinner_start "Downloading"
      if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
        spinner_stop
        die "Could not download GUI package. Check https://github.com/elementmerc/anya/releases for available assets."
      fi
      spinner_stop

      info "Mounting DMG and copying to /Applications…"
      hdiutil attach -quiet "$TMP_FILE" -mountpoint /Volumes/AnyaInstall
      cp -R "/Volumes/AnyaInstall/Anya.app" /Applications/
      hdiutil detach -quiet /Volumes/AnyaInstall
      rm -rf "$TMP_DIR"
      success "Anya.app installed to /Applications"
      ;;

    linux)
      # Prefer .deb on Debian/Ubuntu; fall back to AppImage
      if command -v dpkg >/dev/null 2>&1; then
        ASSET="anya_${VERSION#v}_amd64.deb"
        DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
        TMP_DIR="$(mktemp -d)"
        TMP_FILE="$TMP_DIR/$ASSET"

        info "Downloading $ASSET…"
        spinner_start "Downloading"
        if download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
          spinner_stop
          info "Installing .deb package (may prompt for sudo)…"
          if command -v pkexec >/dev/null 2>&1; then
            pkexec dpkg -i "$TMP_FILE"
          else
            sudo dpkg -i "$TMP_FILE"
          fi
          rm -rf "$TMP_DIR"
          success ".deb installed"
          return
        fi
        spinner_stop
        warn ".deb not available — falling back to AppImage"
      fi

      ASSET="anya_${VERSION#v}_amd64.AppImage"
      DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
      local APPIMAGE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
      local APPIMAGE_BIN="${ANYA_INSTALL_DIR:-$HOME/.local/bin}/anya-gui"
      TMP_DIR="$(mktemp -d)"
      TMP_FILE="$TMP_DIR/$ASSET"

      info "Downloading $ASSET…"
      spinner_start "Downloading"
      if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
        spinner_stop
        die "Could not download AppImage. Check https://github.com/elementmerc/anya/releases"
      fi
      spinner_stop

      mkdir -p "$(dirname "$APPIMAGE_BIN")"
      install -m 755 "$TMP_FILE" "$APPIMAGE_BIN"
      rm -rf "$TMP_DIR"
      success "AppImage installed to $APPIMAGE_BIN"
      ensure_in_path "$(dirname "$APPIMAGE_BIN")"
      ;;

    windows)
      ASSET="Anya_${VERSION#v}_x64_en-US.msi"
      DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
      local DEST="$TEMP\\AnyaInstaller.msi"

      info "Downloading $ASSET…"
      spinner_start "Downloading"
      if ! download "$DOWNLOAD_URL" "$DEST" 2>/dev/null; then
        spinner_stop
        die "Could not download installer. Visit https://github.com/elementmerc/anya/releases"
      fi
      spinner_stop

      info "Launching installer…"
      msiexec //i "$DEST" //passive || die "Installer failed"
      success "Anya GUI installed"
      ;;
  esac
}

# ─── Mode selection ───────────────────────────────────────────────────────────

prompt_mode() {
  header "Anya — installer"
  printf "  What would you like to install?\n\n"
  printf "    ${BOLD}1)${RESET} CLI only   (command-line tool)\n"
  printf "    ${BOLD}2)${RESET} GUI only   (desktop application)\n"
  printf "    ${BOLD}3)${RESET} Both\n\n"
  printf "  Choice [1/2/3, default=1]: "
  read -r _CHOICE </dev/tty
  _CHOICE="${_CHOICE:-1}"

  case "$_CHOICE" in
    1) MODE="cli"  ;;
    2) MODE="gui"  ;;
    3) MODE="both" ;;
    *) warn "Invalid choice '$_CHOICE' — defaulting to CLI only."; MODE="cli" ;;
  esac
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
  detect_platform
  resolve_version

  printf "\n${BOLD}Anya${RESET} ${CYAN}${VERSION}${RESET} — ${OS}/${ARCH}\n"

  # Allow non-interactive mode via ANYA_MODE env var
  if [ -n "${ANYA_MODE:-}" ]; then
    MODE="$ANYA_MODE"
  else
    prompt_mode
  fi

  case "$MODE" in
    cli)  install_cli ;;
    gui)  install_gui ;;
    both) install_cli; install_gui ;;
    *)    die "Unknown mode: $MODE (expected cli, gui, or both)" ;;
  esac

  header "Done"
  if [ "$MODE" = "cli" ] || [ "$MODE" = "both" ]; then
    printf "  Run ${BOLD}anya --help${RESET} to get started.\n"
    printf "  Run ${BOLD}anya verse${RESET} for a word of encouragement.\n"
  fi
  printf "\n"
}

main "$@"
