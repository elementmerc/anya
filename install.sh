#!/usr/bin/env bash
# Anya — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/elementmerc/anya/master/install.sh | bash
#
# Platform support:
#   CLI  : macOS (x86_64, arm64), Linux (x86_64, arm64), Windows (via WSL/Git-Bash)
#   GUI  : macOS (.dmg), Linux (.AppImage / .deb), Windows (.msi)
#
# Environment variables:
#   ANYA_VERSION     — install a specific tag, e.g. ANYA_VERSION=v0.4.0
#   ANYA_NO_COLOR    — set to any non-empty value to disable colour output
#   ANYA_INSTALL_DIR — override CLI install directory (default: $HOME/.local/bin)
#   ANYA_MODE        — skip prompt: "cli", "gui", or "both"

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

# ─── Pre-flight checks ──────────────────────────────────────────────────────

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
    info "WSL detected. Installing Linux binaries."
    info "For the Windows GUI (.msi), download from:"
    info "  https://github.com/elementmerc/anya/releases"
  fi
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
      die "FreeBSD is not yet supported. Use 'cargo install anya-security-core' to build from source."
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

  if command -v curl >/dev/null 2>&1; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/elementmerc/anya/releases/latest" \
      | grep '"tag_name"' \
      | head -1 \
      | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')" || VERSION=""
  elif command -v wget >/dev/null 2>&1; then
    VERSION="$(wget -qO- "https://api.github.com/repos/elementmerc/anya/releases/latest" \
      | grep '"tag_name"' \
      | head -1 \
      | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')" || VERSION=""
  fi

  [ -n "$VERSION" ] || die "Could not determine latest release. Set ANYA_VERSION manually (e.g. ANYA_VERSION=v1.0.2)."
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

  # Verify download is non-empty
  if [ ! -s "$dest" ]; then
    rm -f "$dest"
    return 1
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

  # Post-install verification
  verify_cli
}

install_cli_cargo() {
  info "Installing via cargo (this compiles from source — may take a few minutes)…"
  require_cmd cargo

  # Check Rust version — edition 2024 requires rustc >= 1.85
  local rust_ver
  rust_ver=$(rustc --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
  if [ -n "$rust_ver" ]; then
    local rust_minor
    rust_minor=$(echo "$rust_ver" | cut -d. -f2)
    if [ "$rust_minor" -lt 85 ] 2>/dev/null; then
      error "Anya requires Rust 1.85 or newer (you have rustc $rust_ver)."
      info  "Update with:  rustup update stable"
      info  "Or install rustup from https://rustup.rs"
      die   "Cannot compile from source with this Rust version."
    fi
  fi

  cargo install anya-security-core --locked || die "cargo install failed"
  success "CLI installed via cargo"
}

verify_cli() {
  # Quick smoke test — verify the binary actually runs
  if command -v anya >/dev/null 2>&1; then
    local installed_ver
    installed_ver=$(anya --version 2>/dev/null | head -1)
    if [ -n "$installed_ver" ]; then
      success "Verified: $installed_ver"
    fi
  elif [ -x "${ANYA_INSTALL_DIR:-$HOME/.local/bin}/anya" ]; then
    local installed_ver
    installed_ver=$("${ANYA_INSTALL_DIR:-$HOME/.local/bin}/anya" --version 2>/dev/null | head -1)
    if [ -n "$installed_ver" ]; then
      success "Verified: $installed_ver"
    fi
  fi
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

# ─── Linux GUI dependency check ──────────────────────────────────────────────

check_linux_gui_deps() {
  local missing=""
  for lib in libwebkit2gtk-4.1 libgtk-3; do
    if ! ldconfig -p 2>/dev/null | grep -q "$lib"; then
      missing="$missing $lib"
    fi
  done
  if [ -n "$missing" ]; then
    warn "Missing GUI libraries:$missing"
    # Detect package manager and give appropriate advice
    if command -v apt-get >/dev/null 2>&1; then
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

# ─── GUI install ──────────────────────────────────────────────────────────────

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
      fi

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
      if ! hdiutil attach -quiet "$TMP_FILE" -mountpoint /Volumes/AnyaInstall 2>/dev/null; then
        die "Failed to mount DMG. The download may be corrupt — try again."
      fi
      cp -R "/Volumes/AnyaInstall/Anya.app" /Applications/ 2>/dev/null || {
        hdiutil detach -quiet /Volumes/AnyaInstall 2>/dev/null
        die "Failed to copy Anya.app to /Applications. Check permissions."
      }
      hdiutil detach -quiet /Volumes/AnyaInstall 2>/dev/null
      rm -rf "$TMP_DIR"
      success "Anya.app installed to /Applications"
      info "If macOS blocks Anya, run: xattr -cr /Applications/Anya.app"
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

          # Use apt-get install if available (auto-resolves dependencies)
          # Fall back to dpkg -i + apt-get install -f
          if command -v apt-get >/dev/null 2>&1; then
            if command -v sudo >/dev/null 2>&1; then
              sudo apt-get install -y "$TMP_FILE" 2>/dev/null || {
                sudo dpkg -i "$TMP_FILE" 2>/dev/null
                sudo apt-get install -f -y 2>/dev/null || warn "Some dependencies may be missing. See above."
              }
            elif command -v pkexec >/dev/null 2>&1; then
              pkexec apt-get install -y "$TMP_FILE" 2>/dev/null || {
                pkexec dpkg -i "$TMP_FILE" 2>/dev/null
                pkexec apt-get install -f -y 2>/dev/null || warn "Some dependencies may be missing."
              }
            else
              warn "Neither sudo nor pkexec found."
              warn "Install manually: dpkg -i $TMP_FILE && apt-get install -f -y"
              rm -rf "$TMP_DIR"
              return
            fi
          else
            # No apt-get (maybe a non-Debian system with dpkg?)
            if command -v sudo >/dev/null 2>&1; then
              sudo dpkg -i "$TMP_FILE" 2>/dev/null
            else
              warn "sudo not available. Install manually: dpkg -i $TMP_FILE"
              rm -rf "$TMP_DIR"
              return
            fi
            warn "apt-get not found — cannot auto-resolve dependencies."
            warn "If the GUI fails to start, install: libwebkit2gtk-4.1-0 libgtk-3-0"
          fi

          rm -rf "$TMP_DIR"
          success ".deb installed"
          check_linux_gui_deps
          return
        fi
        spinner_stop
        warn ".deb not available — falling back to AppImage"
      fi

      # AppImage fallback
      # Check FUSE availability
      if ! command -v fusermount >/dev/null 2>&1 && ! command -v fusermount3 >/dev/null 2>&1; then
        warn "FUSE is not installed — AppImage may not run."
        if command -v apt-get >/dev/null 2>&1; then
          info "Install with: sudo apt install fuse libfuse2"
        elif command -v dnf >/dev/null 2>&1; then
          info "Install with: sudo dnf install fuse"
        fi
        info "Or extract manually: ./anya-gui --appimage-extract"
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
      check_linux_gui_deps
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
  preflight
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
