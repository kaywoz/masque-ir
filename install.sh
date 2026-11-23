#!/usr/bin/env bash
# install.sh — installer for masquer (repo masque-ir).
#
# Modes:
#   --check     check prerequisites only; changes nothing (default for now)
#   --dry-run   show what an install would do; changes nothing
#   --verify    check an existing install (models, config folder modes)
#   --help      this text
#
# The install itself is not available yet: it arrives once the masquer
# package exists. Everything goes in the user's profile; no sudo.
#
# Works with bash 3.2 (macOS default) and newer.

set -euo pipefail
trap 'echo "install.sh: failed at line $LINENO" >&2' ERR

PREFIX_DATA="${XDG_DATA_HOME:-$HOME/.local/share}/masquer"
PREFIX_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/masquer"

# Thresholds (GB). Models: GLiNER ~1 GB + Qwen3.5 4B Q4 ~3 GB, plus headroom.
MIN_RAM_GB=8
WARN_RAM_GB=12
MIN_DISK_GB=6

# Hosts the install needs (not masquer itself, which never uses the network).
NET_HOSTS="astral.sh github.com huggingface.co"

fails=0
warns=0

say()  { printf '%-5s %-14s %s\n' "$1" "$2" "$3"; }
pass() { say PASS "$1" "$2"; }
info() { say INFO "$1" "$2"; }
warn() { say WARN "$1" "$2"; warns=$((warns + 1)); }
fail() { say FAIL "$1" "$2"; fails=$((fails + 1)); }

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; }

# --- helpers ---------------------------------------------------------------

os_kind() {
  case "$(uname -s)" in
    Darwin) echo macos ;;
    Linux)
      if [ -r /proc/sys/kernel/osrelease ] &&
         grep -i -E 'microsoft|wsl' /proc/sys/kernel/osrelease >/dev/null 2>&1; then
        echo wsl
      else
        echo linux
      fi ;;
    *) echo other ;;
  esac
}

# Total RAM in whole GB.
ram_total_gb() {
  case "$1" in
    macos) echo $(( $(sysctl -n hw.memsize) / 1073741824 )) ;;
    *)     awk '/^MemTotal:/ {printf "%d", $2 / 1048576}' /proc/meminfo ;;
  esac
}

# Available RAM in whole GB (Linux/WSL only; macOS has no single figure).
ram_avail_gb() {
  awk '/^MemAvailable:/ {printf "%d", $2 / 1048576}' /proc/meminfo
}

# Free disk in whole GB for the first existing parent of a path.
disk_free_gb() {
  d="$1"
  while [ ! -d "$d" ]; do d="$(dirname "$d")"; done
  df -Pk "$d" | awk 'NR == 2 {printf "%d", $4 / 1048576}'
}

has_avx2() {
  case "$1" in
    macos) sysctl -n machdep.cpu.leaf7_features 2>/dev/null | grep -i -w avx2 >/dev/null ;;
    *)     grep -i -w -m1 avx2 /proc/cpuinfo >/dev/null 2>&1 ;;
  esac
}

reachable() {
  curl -sS -o /dev/null -m 10 -I "https://$1" >/dev/null 2>&1
}

# --- checks ----------------------------------------------------------------

run_check() {
  kind="$(os_kind)"
  arch="$(uname -m)"

  echo "masquer prerequisite check"
  echo

  # OS
  case "$kind" in
    macos) pass os "macOS $(sw_vers -productVersion 2>/dev/null || echo '?')" ;;
    linux) pass os "Linux $(uname -r)" ;;
    wsl)   pass os "WSL2 $(uname -r)" ;;
    *)     fail os "$(uname -s) is not supported (Linux, WSL2 or macOS)" ;;
  esac

  # Architecture and AVX2
  case "$arch" in
    x86_64|amd64)
      if has_avx2 "$kind"; then
        pass cpu "$arch with AVX2"
      else
        fail cpu "$arch without AVX2: the local model needs it"
      fi ;;
    arm64|aarch64) pass cpu "$arch" ;;
    *) fail cpu "$arch is not supported (x86_64 or arm64)" ;;
  esac

  # Not root
  if [ "$(id -u)" -eq 0 ]; then
    warn user "running as root: install as your normal user (no sudo needed)"
  else
    pass user "normal user, installs into your profile"
  fi

  # RAM
  if [ "$kind" != other ]; then
    total="$(ram_total_gb "$kind")"
    if [ "$total" -lt "$MIN_RAM_GB" ]; then
      fail ram "${total} GB total; need ${MIN_RAM_GB} GB or more"
    elif [ "$total" -lt "$WARN_RAM_GB" ]; then
      warn ram "${total} GB total; works, but the optional LLM check will be tight"
    else
      pass ram "${total} GB total"
    fi
    if [ "$kind" != macos ]; then
      avail="$(ram_avail_gb)"
      info ram-free "${avail} GB available now"
    fi
    if [ "$kind" = wsl ] && [ "$total" -lt "$WARN_RAM_GB" ]; then
      info wsl-memory "raise memory= in %UserProfile%\\.wslconfig, then run: wsl --shutdown"
    fi
  fi

  # Disk
  free="$(disk_free_gb "$PREFIX_DATA")"
  if [ "$free" -lt "$MIN_DISK_GB" ]; then
    fail disk "${free} GB free for $PREFIX_DATA; need ${MIN_DISK_GB} GB"
  else
    pass disk "${free} GB free for $PREFIX_DATA"
  fi

  # Disk encryption
  case "$kind" in
    macos)
      if fdesetup status 2>/dev/null | grep 'FileVault is On' >/dev/null; then
        pass encryption "FileVault is on"
      else
        warn encryption "FileVault is not on: case folders and mapping stores would be unencrypted"
      fi ;;
    wsl)   info encryption "can't be read from WSL: check BitLocker on C: in Windows" ;;
    linux) info encryption "not checked: make sure your home is on an encrypted disk" ;;
  esac

  # uv
  if command -v uv >/dev/null 2>&1; then
    pass uv "$(uv --version 2>/dev/null || echo present)"
  else
    warn uv "not installed: the installer will add it to your profile"
  fi

  # curl (needed for the install only)
  if command -v curl >/dev/null 2>&1; then
    pass curl "present"
    for h in $NET_HOSTS; do
      if reachable "$h"; then
        pass net "$h reachable"
      else
        case "$h" in
          astral.sh)      hint="install uv by hand, or ask IT to allow it" ;;
          huggingface.co) hint="copy the models in later with --models-from DIR" ;;
          *)              hint="needed for the release download; ask IT to allow it" ;;
        esac
        warn net "$h not reachable: $hint"
      fi
    done
  else
    fail curl "missing: needed to download uv and the models"
  fi

  # Optional container runtime
  rt=""
  command -v podman >/dev/null 2>&1 && rt="podman $(podman --version 2>/dev/null | awk '{print $3}')"
  if command -v docker >/dev/null 2>&1; then
    [ -n "$rt" ] && rt="$rt, "
    rt="${rt}docker $(docker --version 2>/dev/null | awk '{print $3}' | tr -d ,)"
  fi
  if [ -n "$rt" ]; then
    info container "optional runtime found: $rt"
  else
    info container "no Docker or Podman: fine, the container mode is optional"
  fi
  if [ "$kind" = macos ]; then
    if command -v krunkit >/dev/null 2>&1; then
      info gpu-container "krunkit found: Podman containers can use the GPU"
    else
      info gpu-container "no krunkit: containers run CPU-only (native install uses Metal)"
    fi
  fi

  echo
  echo "Result: $fails failed, $warns warnings"
  [ "$fails" -eq 0 ]
}

run_verify() {
  echo "masquer install verification"
  echo
  if [ -d "$PREFIX_DATA" ]; then
    pass data "$PREFIX_DATA exists"
  else
    fail data "$PREFIX_DATA missing: masquer is not installed yet"
  fi
  if [ -d "$PREFIX_CONF" ]; then
    m="$(stat -c %a "$PREFIX_CONF" 2>/dev/null || stat -f %Lp "$PREFIX_CONF")"
    if [ "$m" = 700 ]; then
      pass config "$PREFIX_CONF is mode 700"
    else
      fail config "$PREFIX_CONF is mode $m; run: chmod 700 '$PREFIX_CONF'"
    fi
  else
    info config "$PREFIX_CONF missing: no deny-lists yet"
  fi
  if command -v masquer >/dev/null 2>&1; then
    pass masquer "$(command -v masquer)"
  else
    fail masquer "command not found"
  fi
  echo
  echo "Result: $fails failed, $warns warnings"
  [ "$fails" -eq 0 ]
}

run_dry_run() {
  echo "Dry run: an install would"
  echo "  1. install uv into your profile if it's missing"
  echo "  2. install masquer from the latest tagged release with uv"
  echo "  3. download the pinned models into $PREFIX_DATA/models and check their SHA256"
  echo "  4. create $PREFIX_CONF for the local deny-lists (mode 700)"
  echo "Nothing is changed. The install itself is not available yet."
}

# --- main ------------------------------------------------------------------

mode="${1:---check}"
case "$mode" in
  --check)   if run_check; then exit 0; else exit 1; fi ;;
  --verify)  if run_verify; then exit 0; else exit 1; fi ;;
  --dry-run) run_dry_run ;;
  --help|-h) usage ;;
  *) echo "install.sh: the install itself is not available yet; use --check" >&2
     usage >&2
     exit 2 ;;
esac
