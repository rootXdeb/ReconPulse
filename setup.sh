#!/usr/bin/env bash
#
# Reconpulse — Linux setup script
# Installs build requirements, compiles the scanner, and (optionally) grants the
# raw-socket capability needed for SYN scanning and ICMP host discovery.
#
# Usage:
#   ./setup.sh              # install deps + build
#   ./setup.sh --caps       # also grant CAP_NET_RAW to the built binary
#   ./setup.sh --no-install # skip package install, just build
#
set -euo pipefail

# ---- pretty output -----------------------------------------------------------
c_reset=$'\033[0m'; c_grn=$'\033[1;32m'; c_ylw=$'\033[1;33m'; c_red=$'\033[1;31m'; c_dim=$'\033[2m'
say()  { printf '%s[reconpulse]%s %s\n' "$c_grn" "$c_reset" "$*"; }
warn() { printf '%s[reconpulse]%s %s\n' "$c_ylw" "$c_reset" "$*"; }
die()  { printf '%s[reconpulse]%s %s\n' "$c_red" "$c_reset" "$*" >&2; exit 1; }

# ---- args --------------------------------------------------------------------
DO_INSTALL=1
DO_CAPS=0
for arg in "$@"; do
  case "$arg" in
    --no-install) DO_INSTALL=0 ;;
    --caps)       DO_CAPS=1 ;;
    -h|--help)
      cat <<'USAGE'
Reconpulse — Linux setup script

Usage:
  ./setup.sh              install build deps, then compile
  ./setup.sh --caps       also grant CAP_NET_RAW to the binary (SYN/ICMP without sudo)
  ./setup.sh --no-install skip package install, just compile
  ./setup.sh --help       show this help
USAGE
      exit 0 ;;
    *) die "unknown option: $arg (try --help)" ;;
  esac
done

cd "$(dirname "$0")"

[ "$(uname -s)" = "Linux" ] || warn "This script targets Linux. On macOS/other POSIX just run 'make'."

# ---- privilege helper --------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    warn "Not root and 'sudo' not found — package install and --caps may fail."
  fi
fi

# ---- detect package manager --------------------------------------------------
detect_pm() {
  for pm in apt-get dnf yum pacman zypper apk; do
    command -v "$pm" >/dev/null 2>&1 && { echo "$pm"; return; }
  done
  echo ""
}

install_deps() {
  local pm; pm="$(detect_pm)"
  [ -n "$pm" ] || die "No supported package manager found. Install a C11 compiler, make, and (optional) vim/xxd manually."
  say "Installing build requirements via ${pm} ..."
  case "$pm" in
    apt-get)
      $SUDO apt-get update -y
      $SUDO apt-get install -y build-essential gcc make libcap2-bin xxd ;;
    dnf)
      $SUDO dnf install -y gcc make libcap glibc-devel vim-common ;;
    yum)
      $SUDO yum install -y gcc make libcap glibc-devel vim-common ;;
    pacman)
      $SUDO pacman -Sy --noconfirm --needed base-devel gcc make libcap ;;
    zypper)
      $SUDO zypper install -y gcc make libcap-progs glibc-devel vim ;;
    apk)
      $SUDO apk add --no-cache build-base gcc make libcap xxd ;;
  esac
}

# ---- run ---------------------------------------------------------------------
if [ "$DO_INSTALL" -eq 1 ]; then
  install_deps
else
  say "Skipping package install (--no-install)."
fi

command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || die "No C compiler on PATH after install."
command -v make >/dev/null 2>&1 || die "'make' not found after install."

say "Building Reconpulse ..."
make clean >/dev/null 2>&1 || true
make

[ -x ./reconpulse ] || die "Build did not produce ./reconpulse"
say "Build complete: $(pwd)/reconpulse"

# ---- optional raw-socket capability -----------------------------------------
if [ "$DO_CAPS" -eq 1 ]; then
  if command -v setcap >/dev/null 2>&1; then
    say "Granting CAP_NET_RAW (SYN scan + ICMP discovery without sudo) ..."
    if $SUDO setcap cap_net_raw+ep ./reconpulse; then
      say "Capability set. SYN/ICMP scanning will work without root."
    else
      warn "setcap failed — run SYN/ICMP scans with sudo instead."
    fi
  else
    warn "'setcap' not available — run SYN/ICMP scans with sudo instead."
  fi
else
  printf '%s' "$c_dim"
  echo "Note: SYN scanning and ICMP discovery need root or CAP_NET_RAW."
  echo "      Re-run with '--caps' to grant it, or launch with sudo."
  printf '%s' "$c_reset"
fi

# ---- done --------------------------------------------------------------------
cat <<EOF

${c_grn}Reconpulse is ready.${c_reset}

  CLI scan     ./reconpulse -t 192.168.56.101 --authorize
  Full range   ./reconpulse -t 192.168.56.0/24 -p 1-9000 --threads 100 --authorize
  Web console  ./reconpulse --serve --web-port 8888 --authorize   ${c_dim}# then open http://localhost:8888${c_reset}
  Help         ./reconpulse --help

Only scan systems you own or are explicitly authorized to test.
EOF
