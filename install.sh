#!/usr/bin/env bash
# Anya — one-line installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash -s -- --both
#   curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash -s -- --gui
#   bash install.sh --cli
#
# Platform support:
#   CLI  : macOS (x86_64, arm64), Linux (x86_64, arm64), Windows (via WSL/Git-Bash)
#   GUI  : macOS (.dmg), Linux (.AppImage / .deb), Windows (.msi)
#
# Flags:
#   --cli          Install CLI only (skip prompt)
#   --gui          Install GUI only (skip prompt)
#   --both         Install CLI and GUI (skip prompt)
#   --help         Show this help message
#
# Environment variables (override flags):
#   ANYA_VERSION     — install a specific tag, e.g. ANYA_VERSION=v0.4.0
#   ANYA_NO_COLOR    — set to any non-empty value to disable colour output
#   ANYA_INSTALL_DIR — override CLI install directory (default: $HOME/.local/bin)
#   ANYA_MODE        — skip prompt: "cli", "gui", or "both"

set -uo pipefail

INSTALLED_FILES=()
_CLEANUP_DIRS=()
track_install() { INSTALLED_FILES+=("$1"); }
track_tmpdir()  { _CLEANUP_DIRS+=("$1"); }

cleanup_on_exit() {
  local exit_code=$?
  # Always clean up temp dirs
  for d in "${_CLEANUP_DIRS[@]}"; do
    rm -rf "$d" 2>/dev/null
  done
  # Rollback installed files on error
  if [ $exit_code -ne 0 ] && [ ${#INSTALLED_FILES[@]} -gt 0 ]; then
    warn "Installation failed — rolling back…"
    for f in "${INSTALLED_FILES[@]}"; do
      rm -rf "$f" 2>/dev/null && info "  Removed $f"
    done
  fi
}
trap cleanup_on_exit EXIT

# ─── TTY detection ────────────────────────────────────────────────────────────
# When piped (curl ... | bash), stdin is the pipe, not the terminal.
# We can still prompt the user via /dev/tty if it exists.

CAN_PROMPT=false
if [ -e /dev/tty ]; then
  CAN_PROMPT=true
fi

# Read from the user's terminal, even when the script is piped
prompt_read() {
  local prompt="$1" varname="$2" default="${3:-}"
  if [ "$CAN_PROMPT" = true ]; then
    printf "%s" "$prompt"
    read -r "$varname" </dev/tty 2>/dev/null || eval "$varname='$default'"
  else
    eval "$varname='$default'"
  fi
}

# ─── Colours ──────────────────────────────────────────────────────────────────
# Check if the terminal (stdout) supports colour — even when stdin is piped

if [ -z "${ANYA_NO_COLOR:-}" ] && { [ -t 1 ] || [ -t 2 ]; }; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; CYAN=''; BOLD=''; RESET=''
fi

# ─── Helpers ──────────────────────────────────────────────────────────────────

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

make_tmpdir() {
  local d
  d=$(mktemp -d 2>/dev/null) || { d="/tmp/anya-install-$$-$RANDOM"; mkdir -p "$d"; }
  track_tmpdir "$d"
  echo "$d"
}

show_help() {
  cat <<'HELP'
Anya — one-line installer

Usage:
  curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/main/install.sh | bash
  curl -fsSL ...install.sh | bash -s -- --both
  bash install.sh [--cli | --gui | --both] [--help]

Flags:
  --cli     Install CLI only (command-line tool)
  --gui     Install GUI only (desktop application)
  --both    Install CLI and GUI
  --help    Show this help message

Environment variables:
  ANYA_VERSION      Install a specific version (e.g. ANYA_VERSION=v1.1.0)
  ANYA_NO_COLOR     Disable coloured output
  ANYA_INSTALL_DIR  Override CLI install directory (default: ~/.local/bin)
  ANYA_MODE         Same as flags: "cli", "gui", or "both"
HELP
  exit 0
}

# ─── Argument parsing ─────────────────────────────────────────────────────────

parse_args() {
  for arg in "$@"; do
    case "$arg" in
      --cli)   ANYA_MODE="cli"  ;;
      --gui)   ANYA_MODE="gui"  ;;
      --both)  ANYA_MODE="both" ;;
      --help|-h) show_help      ;;
      *)
        warn "Unknown argument: $arg"
        info "Run with --help for usage"
        ;;
    esac
  done
}

# ─── Pre-flight checks ───────────────────────────────────────────────────────

preflight() {
  # Ensure we have a download tool
  if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    die "Neither curl nor wget found. Install one and retry."
  fi

  # Check disk space (need ~200MB for GUI)
  local install_dir="${ANYA_INSTALL_DIR:-$HOME/.local/bin}"
  local free_mb
  free_mb=$(df -m "$HOME" 2>/dev/null | awk 'NR==2{print $4}') || free_mb=""
  if [ -n "$free_mb" ] && [ "$free_mb" -lt 200 ] 2>/dev/null; then
    warn "Low disk space (${free_mb}MB free). Installation may fail."
  fi

  # Check write permissions on install directory
  mkdir -p "$install_dir" 2>/dev/null || true
  if [ -d "$install_dir" ] && [ ! -w "$install_dir" ]; then
    warn "Cannot write to $install_dir"
    info "Set ANYA_INSTALL_DIR to a writable directory, or run with appropriate permissions."
  fi

  # WSL detection — users may expect Windows binaries
  if [ "$(uname -s)" = "Linux" ] && grep -qi microsoft /proc/version 2>/dev/null; then
    IS_WSL=true
    info "WSL detected. Installing Linux binaries."
    info "For the Windows GUI (.msi), download from:"
    info "  https://github.com/elementmerc/anya/releases"
  fi

  # Proxy detection
  if [ -n "${https_proxy:-}" ] || [ -n "${http_proxy:-}" ] || [ -n "${HTTPS_PROXY:-}" ] || [ -n "${HTTP_PROXY:-}" ]; then
    info "Proxy detected: ${https_proxy:-${http_proxy:-${HTTPS_PROXY:-${HTTP_PROXY}}}}"
  fi

  # Network connectivity check (with timeout so we don't hang)
  local _net_ok=false
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --connect-timeout 10 --max-time 15 "https://api.github.com" >/dev/null 2>&1; then
      _net_ok=true
    fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q --timeout=15 --spider "https://api.github.com" 2>/dev/null; then
      _net_ok=true
    fi
  fi

  if [ "$_net_ok" = false ]; then
    error "Cannot reach GitHub."
    info  "Check your internet connection or proxy settings."
    info  "Download Anya manually from: https://github.com/elementmerc/anya/releases"
    die   "Cannot proceed without network access."
  fi
}

# ─── Platform detection ──────────────────────────────────────────────────────

IS_WSL=false

detect_platform() {
  _OS="$(uname -s)"
  _ARCH="$(uname -m)"

  case "$_OS" in
    Linux)
      OS="linux"
      case "$_ARCH" in
        x86_64)  ARCH="x86_64"  ;;
        aarch64) ARCH="aarch64" ;;
        armv7l)  ARCH="aarch64"; warn "armv7l detected — attempting aarch64 binary" ;;
        *)       die "Unsupported Linux architecture: $_ARCH" ;;
      esac
      ;;
    Darwin)
      OS="macos"
      ARCH="universal"
      ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
      OS="windows"
      ARCH="x86_64"
      ;;
    FreeBSD)
      die "FreeBSD is not yet supported. Check https://github.com/elementmerc/anya/releases"
      ;;
    *)
      die "Unsupported OS: $_OS"
      ;;
  esac
}

# ─── Version resolution ─────────────────────────────────────────────────────

resolve_version() {
  if [ -n "${ANYA_VERSION:-}" ]; then
    VERSION="$ANYA_VERSION"
    return
  fi

  info "Fetching latest release version…"

  local _api_response=""
  if command -v curl >/dev/null 2>&1; then
    _api_response="$(curl -fsSL --connect-timeout 10 --max-time 15 \
      "https://api.github.com/repos/elementmerc/anya/releases/latest" 2>/dev/null)" || _api_response=""
  elif command -v wget >/dev/null 2>&1; then
    _api_response="$(wget -qO- --timeout=15 \
      "https://api.github.com/repos/elementmerc/anya/releases/latest" 2>/dev/null)" || _api_response=""
  fi

  if [ -z "$_api_response" ]; then
    die "Could not fetch release info from GitHub. Set ANYA_VERSION manually (e.g. ANYA_VERSION=v1.1.0)."
  fi

  VERSION="$(echo "$_api_response" \
    | grep '"tag_name"' \
    | head -1 \
    | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')" || VERSION=""

  [ -n "$VERSION" ] || die "Could not parse release version. Set ANYA_VERSION manually (e.g. ANYA_VERSION=v1.1.0)."
}

# ─── Download helper ─────────────────────────────────────────────────────────

download() {
  local url="$1" dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 15 --max-time 300 --retry 3 --retry-delay 2 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=300 --tries=3 -O "$dest" "$url"
  else
    die "Neither curl nor wget found. Install one and retry."
  fi

  # Verify download is non-empty
  if [ ! -s "$dest" ]; then
    rm -f "$dest"
    return 1
  fi
}

# ─── Upgrade detection ───────────────────────────────────────────────────────

detect_existing() {
  if command -v anya >/dev/null 2>&1; then
    local current
    current=$(anya --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -n "$current" ]; then
      if [ "$current" = "${VERSION#v}" ]; then
        info "Anya ${current} is already installed and up to date."
        if [ "$CAN_PROMPT" = true ]; then
          local choice=""
          prompt_read "  Reinstall? [y/N] " choice "n"
          [[ "$choice" =~ ^[Yy] ]] || { success "Nothing to do."; exit 0; }
        else
          info "Reinstalling (non-interactive)."
        fi
      else
        info "Upgrading Anya: ${current} → ${VERSION#v}"
      fi
    fi
  fi
}

# ─── Checksum verification ──────────────────────────────────────────────────

verify_checksum() {
  local file="$1" checksum_url="$2"
  local checksum_file="${file}.sha256"

  # Try to download checksum file
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --connect-timeout 10 --max-time 30 -o "$checksum_file" "$checksum_url" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q --timeout=30 -O "$checksum_file" "$checksum_url" 2>/dev/null
  fi

  if [ ! -s "$checksum_file" ]; then
    warn "No checksum file available — skipping integrity verification"
    rm -f "$checksum_file"
    return 0
  fi

  local expected actual
  expected=$(awk '{print $1}' "$checksum_file")
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    warn "No SHA-256 tool available — skipping integrity verification"
    rm -f "$checksum_file"
    return 0
  fi

  rm -f "$checksum_file"

  if [ "$expected" = "$actual" ]; then
    info "Integrity verified ✓"
    return 0
  else
    error "Checksum mismatch!"
    error "  Expected: ${expected}"
    error "  Got:      ${actual}"
    die "Download may be corrupted. Please try again."
  fi
}

# ─── CLI install ─────────────────────────────────────────────────────────────

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
  TMP_DIR=$(make_tmpdir)
  local TMP_FILE="$TMP_DIR/$ASSET"

  info "Downloading $ASSET…"
  spinner_start "Downloading"

  if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
    spinner_stop
    warn "Pre-built binary not found for $OS/$ARCH"
    install_cli_fallback
    return
  fi
  spinner_stop
  verify_checksum "$TMP_FILE" "${DOWNLOAD_URL}.sha256"

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
  EXTRACTED_BINARY="$(find "$TMP_DIR" -name "$BINARY_NAME" -not -name "*.tar.gz" -not -name "*.zip" | head -1)"
  [ -n "$EXTRACTED_BINARY" ] || die "Could not find binary '$BINARY_NAME' in the downloaded archive."

  install -m 755 "$EXTRACTED_BINARY" "$INSTALL_DIR/$BINARY_NAME"
  track_install "$INSTALL_DIR/$BINARY_NAME"

  success "CLI installed to $INSTALL_DIR/$BINARY_NAME"
  ensure_in_path "$INSTALL_DIR"

  # Post-install verification
  verify_cli
}

install_cli_fallback() {
  # Tier 2: Try musl static binary (works on any Linux)
  if [ "$OS" = "linux" ]; then
    info "Trying statically-linked musl binary…"
    local musl_asset="anya-${VERSION}-${ARCH}-unknown-linux-musl.tar.gz"
    local musl_url="https://github.com/elementmerc/anya/releases/download/${VERSION}/${musl_asset}"
    local TMP_DIR
    TMP_DIR=$(make_tmpdir)
    local musl_file="$TMP_DIR/$musl_asset"

    if download "$musl_url" "$musl_file" 2>/dev/null && [ -s "$musl_file" ]; then
      verify_checksum "$musl_file" "${musl_url}.sha256"

      local INSTALL_DIR="${ANYA_INSTALL_DIR:-$HOME/.local/bin}"
      mkdir -p "$INSTALL_DIR"
      tar -xzf "$musl_file" -C "$TMP_DIR"
      local EXTRACTED
      EXTRACTED="$(find "$TMP_DIR" -name "anya" -not -name "*.tar.gz" | head -1)"
      if [ -n "$EXTRACTED" ]; then
        install -m 755 "$EXTRACTED" "$INSTALL_DIR/anya"
        track_install "$INSTALL_DIR/anya"
        success "CLI installed to $INSTALL_DIR/anya (static musl)"
        ensure_in_path "$INSTALL_DIR"
        verify_cli
        return 0
      fi
    fi
    warn "No static binary available for ${ARCH}"
  fi

  # Tier 3: Docker wrapper fallback
  if command -v docker >/dev/null 2>&1; then
    info "Falling back to Docker image…"
    if docker pull "elementmerc/anya:${VERSION#v}" 2>/dev/null || docker pull "elementmerc/anya:latest" 2>/dev/null; then
      local wrapper="${ANYA_INSTALL_DIR:-$HOME/.local/bin}/anya"
      mkdir -p "$(dirname "$wrapper")"
      cat > "$wrapper" << 'DOCKERWRAPPER'
#!/bin/sh
exec docker run --rm -v "$(pwd):/work:ro" -w /work elementmerc/anya:latest "$@"
DOCKERWRAPPER
      chmod 755 "$wrapper"
      track_install "$wrapper"
      success "Installed via Docker wrapper at $wrapper"
      info "Note: requires Docker running. Use 'docker pull elementmerc/anya:latest' to update."
      return 0
    fi
    warn "Docker pull failed"
  fi

  error "No installation method available for your platform (${OS}/${ARCH})."
  info  "Options:"
  info  "  1. Download manually: https://github.com/elementmerc/anya/releases"
  info  "  2. Use Docker: docker run --rm -v \$(pwd):/work:ro elementmerc/anya:latest --file /work/sample.exe"
  die   "Installation failed — no compatible binary found."
}

verify_cli() {
  # Quick smoke test — verify the binary actually runs
  local bin_path="${ANYA_INSTALL_DIR:-$HOME/.local/bin}/anya"

  if command -v anya >/dev/null 2>&1; then
    bin_path="$(command -v anya)"
  fi

  if [ -x "$bin_path" ]; then
    local installed_ver
    installed_ver=$("$bin_path" --version 2>/dev/null | head -1) || installed_ver=""
    if [ -n "$installed_ver" ]; then
      success "Verified: $installed_ver"
    else
      warn "Binary installed but --version returned nothing. It may still work."
    fi
  fi
}

ensure_in_path() {
  local dir="$1"
  case ":$PATH:" in
    *":$dir:"*) ;;
    *)
      warn "$dir is not in your PATH."
      info "Add to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
      printf "\n    export PATH=\"%s:\$PATH\"\n\n" "$dir"
      ;;
  esac
}

# ─── Linux GUI availability check ───────────────────────────────────────────

# Determine what GUI format is available for this Linux system
detect_linux_gui_format() {
  # .deb requires WebKitGTK 4.1 (Ubuntu 22.04+ / Debian 12+)
  if command -v dpkg >/dev/null 2>&1; then
    if command -v apt-cache >/dev/null 2>&1 && apt-cache show libwebkit2gtk-4.1-0 >/dev/null 2>&1; then
      LINUX_GUI_FORMAT="deb"
      return
    fi
  fi
  # AppImage works everywhere (bundles dependencies)
  LINUX_GUI_FORMAT="appimage"
}

check_linux_gui_deps() {
  local missing=""
  for lib in libwebkit2gtk-4.1 libgtk-3; do
    if ! ldconfig -p 2>/dev/null | grep -q "$lib"; then
      missing="$missing $lib"
    fi
  done
  if [ -n "$missing" ]; then
    warn "Missing GUI libraries:$missing"
    if command -v apt-cache >/dev/null 2>&1 && ! apt-cache show libwebkit2gtk-4.1-0 >/dev/null 2>&1; then
      warn "Your system does not have WebKitGTK 4.1 available (requires Ubuntu 22.04+ / Debian 12+)."
      info "Use the AppImage instead — it bundles all dependencies."
      info "Download from: https://github.com/elementmerc/anya/releases"
    elif command -v apt-get >/dev/null 2>&1; then
      info "Install with: sudo apt install libwebkit2gtk-4.1-0 libgtk-3-0"
    elif command -v dnf >/dev/null 2>&1; then
      info "Install with: sudo dnf install webkit2gtk4.1 gtk3"
    elif command -v pacman >/dev/null 2>&1; then
      info "Install with: sudo pacman -S webkit2gtk-4.1 gtk3"
    else
      info "Install libwebkit2gtk-4.1 and libgtk-3 using your package manager."
    fi
    info "The CLI works without these — only the GUI needs them."
  fi
}

# ─── GUI install ─────────────────────────────────────────────────────────────

install_gui() {
  header "Installing Anya GUI"

  local ASSET DOWNLOAD_URL TMP_DIR TMP_FILE

  case "$OS" in
    macos)
      # Check macOS version (need 11.0+ / Big Sur)
      local mac_ver
      mac_ver=$(sw_vers -productVersion 2>/dev/null | cut -d. -f1) || mac_ver=""
      if [ -n "$mac_ver" ] && [ "$mac_ver" -lt 11 ] 2>/dev/null; then
        warn "Anya GUI requires macOS 11.0 (Big Sur) or newer."
        warn "You have macOS $(sw_vers -productVersion 2>/dev/null). The CLI will still work."
        return 1
      fi

      ASSET="Anya_${VERSION#v}_universal.dmg"
      DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
      TMP_DIR=$(make_tmpdir)
      TMP_FILE="$TMP_DIR/$ASSET"

      info "Downloading $ASSET…"
      spinner_start "Downloading"
      if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
        spinner_stop
        error "Could not download GUI package."
        info  "Check https://github.com/elementmerc/anya/releases for available assets."
        return 1
      fi
      spinner_stop
      verify_checksum "$TMP_FILE" "${DOWNLOAD_URL}.sha256"

      info "Mounting DMG and copying to /Applications…"
      hdiutil detach -quiet /Volumes/AnyaInstall 2>/dev/null || true
      if ! hdiutil attach -quiet "$TMP_FILE" -mountpoint /Volumes/AnyaInstall 2>/dev/null; then
        die "Failed to mount DMG. The download may be corrupt — try again."
      fi
      cp -R "/Volumes/AnyaInstall/Anya.app" /Applications/ 2>/dev/null || {
        hdiutil detach -quiet /Volumes/AnyaInstall 2>/dev/null
        die "Failed to copy Anya.app to /Applications. Check permissions."
      }
      hdiutil detach -quiet /Volumes/AnyaInstall 2>/dev/null
      # Strip macOS quarantine flag to avoid Gatekeeper block (app is unsigned)
      xattr -cr /Applications/Anya.app 2>/dev/null || true
      track_install "/Applications/Anya.app"
      success "Anya.app installed to /Applications"
      info "Quarantine flag cleared — Anya will open without Gatekeeper prompts."
      ;;

    linux)
      detect_linux_gui_format

      if [ "$LINUX_GUI_FORMAT" = "deb" ]; then
        _install_gui_deb && return 0
        warn ".deb install failed — trying AppImage instead"
      fi

      _install_gui_appimage
      ;;

    windows)
      ASSET="Anya_${VERSION#v}_x64_en-US.msi"
      DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
      TMP_DIR=$(make_tmpdir)
      TMP_FILE="$TMP_DIR/AnyaInstaller.msi"

      info "Downloading $ASSET…"
      spinner_start "Downloading"
      if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
        spinner_stop
        error "Could not download installer."
        info  "Visit https://github.com/elementmerc/anya/releases"
        return 1
      fi
      spinner_stop
      verify_checksum "$TMP_FILE" "${DOWNLOAD_URL}.sha256"

      info "Launching installer…"
      msiexec //i "$TMP_FILE" //passive || die "Installer failed"
      success "Anya GUI installed"
      ;;
  esac
}

_install_gui_deb() {
  local ASSET="anya_${VERSION#v}_amd64.deb"
  local DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
  local TMP_DIR
  TMP_DIR=$(make_tmpdir)
  local TMP_FILE="$TMP_DIR/$ASSET"

  info "Downloading $ASSET…"
  spinner_start "Downloading"
  if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
    spinner_stop
    return 1
  fi
  spinner_stop
  verify_checksum "$TMP_FILE" "${DOWNLOAD_URL}.sha256"

  info "Installing .deb package (may prompt for sudo)…"

  local _installed=false
  if command -v apt-get >/dev/null 2>&1; then
    if command -v sudo >/dev/null 2>&1; then
      if sudo apt-get install -y "$TMP_FILE" 2>/dev/null; then
        _installed=true
      elif sudo dpkg -i "$TMP_FILE" 2>/dev/null; then
        sudo apt-get install -f -y 2>/dev/null || warn "Some dependencies may be missing."
        _installed=true
      fi
    elif command -v pkexec >/dev/null 2>&1; then
      if pkexec apt-get install -y "$TMP_FILE" 2>/dev/null; then
        _installed=true
      fi
    fi
  fi

  if [ "$_installed" = false ]; then
    warn "Could not install .deb automatically."
    info "Install manually: sudo dpkg -i $TMP_FILE && sudo apt-get install -f -y"
    return 1
  fi

  success ".deb installed"
  check_linux_gui_deps
  return 0
}

_install_gui_appimage() {
  # Check FUSE availability
  if ! command -v fusermount >/dev/null 2>&1 && ! command -v fusermount3 >/dev/null 2>&1; then
    warn "FUSE is not installed — AppImage may not run without it."
    if command -v apt-get >/dev/null 2>&1; then
      info "Install with: sudo apt install fuse libfuse2"
    elif command -v dnf >/dev/null 2>&1; then
      info "Install with: sudo dnf install fuse"
    fi
    info "Or extract manually: ./anya-gui --appimage-extract"
  fi

  local ASSET="anya_${VERSION#v}_amd64.AppImage"
  local DOWNLOAD_URL="https://github.com/elementmerc/anya/releases/download/${VERSION}/${ASSET}"
  local APPIMAGE_BIN="${ANYA_INSTALL_DIR:-$HOME/.local/bin}/anya-gui"
  local TMP_DIR
  TMP_DIR=$(make_tmpdir)
  local TMP_FILE="$TMP_DIR/$ASSET"

  info "Downloading $ASSET…"
  spinner_start "Downloading"
  if ! download "$DOWNLOAD_URL" "$TMP_FILE" 2>/dev/null; then
    spinner_stop
    error "Could not download AppImage."
    info  "Download manually: https://github.com/elementmerc/anya/releases"
    return 1
  fi
  spinner_stop
  verify_checksum "$TMP_FILE" "${DOWNLOAD_URL}.sha256"

  mkdir -p "$(dirname "$APPIMAGE_BIN")"
  install -m 755 "$TMP_FILE" "$APPIMAGE_BIN"
  track_install "$APPIMAGE_BIN"
  success "AppImage installed to $APPIMAGE_BIN"
  ensure_in_path "$(dirname "$APPIMAGE_BIN")"
  check_linux_gui_deps
}

# ─── Mode selection ──────────────────────────────────────────────────────────

prompt_mode() {
  header "Anya — installer"

  # Show platform-specific context
  printf "  Platform: ${BOLD}%s/%s${RESET}" "$OS" "$ARCH"
  if [ "$IS_WSL" = true ]; then
    printf " (WSL)"
  fi
  printf "\n"

  # Show what GUI format will be used
  local gui_note=""
  case "$OS" in
    linux)
      detect_linux_gui_format
      if [ "$LINUX_GUI_FORMAT" = "deb" ]; then
        gui_note="(.deb package)"
      else
        gui_note="(.AppImage — bundles all deps)"
      fi
      ;;
    macos)   gui_note="(.dmg)" ;;
    windows) gui_note="(.msi)" ;;
  esac

  printf "\n  What would you like to install?\n\n"
  printf "    ${BOLD}1)${RESET} CLI only   — command-line tool\n"
  printf "    ${BOLD}2)${RESET} GUI only   — desktop application %s\n" "$gui_note"
  printf "    ${BOLD}3)${RESET} Both       — CLI + GUI (recommended)\n\n"

  if [ "$CAN_PROMPT" = false ]; then
    # Truly no way to prompt — default to both
    info "No terminal available for prompt — installing both CLI and GUI."
    info "Use --cli, --gui, or --both to choose a specific mode."
    MODE="both"
    return
  fi

  local _choice=""
  prompt_read "  Choice [1/2/3, default=3]: " _choice "3"

  case "$_choice" in
    1|cli)   MODE="cli"  ;;
    2|gui)   MODE="gui"  ;;
    3|both)  MODE="both" ;;
    *)       warn "Invalid choice '$_choice' — installing both."; MODE="both" ;;
  esac
}

# ─── Main ────────────────────────────────────────────────────────────────────

main() {
  parse_args "$@"
  detect_platform
  preflight
  resolve_version
  detect_existing

  printf "\n${BOLD}Anya${RESET} ${CYAN}${VERSION}${RESET} — ${OS}/${ARCH}\n"

  # Determine installation mode: flag/env > prompt
  if [ -n "${ANYA_MODE:-}" ]; then
    MODE="$ANYA_MODE"
    info "Installing: $MODE"
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
  if [ "$MODE" = "gui" ] || [ "$MODE" = "both" ]; then
    case "$OS" in
      macos)   printf "  Open ${BOLD}Anya${RESET} from Applications or Spotlight.\n" ;;
      linux)   printf "  Run ${BOLD}anya-gui${RESET} to launch the desktop app.\n" ;;
      windows) printf "  Launch ${BOLD}Anya${RESET} from the Start Menu.\n" ;;
    esac
  fi
  printf "\n"
}

main "$@"
