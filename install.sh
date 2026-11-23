#!/usr/bin/env bash
# install.sh — installer for masquer (repo masque-ir).
#
# Modes:
#   (none)      check prerequisites, then install uv (if missing) and masquer
#   --check     check prerequisites only; changes nothing
#   --dry-run   show what an install would do; changes nothing
#   --verify    check an existing install
#   --ref REF   install this tag or branch instead of the latest release
#   --help      this text
#
# Everything goes in the user's profile (~/.local); no sudo. Models are not
# installed yet: they arrive with the detection stage.
#
# Works with bash 3.2 (macOS default) and newer.

set -euo pipefail
trap 'echo "install.sh: failed at line $LINENO" >&2' ERR

PREFIX_DATA="${XDG_DATA_HOME:-$HOME/.local/share}/masquer"
PREFIX_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/masquer"

# Thresholds. Models: GLiNER ~1 GB + Qwen3.5 4B Q4 ~3 GB, plus headroom.
# RAM in MiB with 0.5 GiB slack: the kernel reserves memory, so an 8 GB
# machine or WSL VM reports roughly 7.6-7.9 GiB in MemTotal.
MIN_RAM_MIB=7680    # "8 GB"
WARN_RAM_MIB=11776  # "12 GB"
MIN_DISK_GB=6

# Hosts the install needs (not masquer itself, which never uses the network).
NET_HOSTS="github.com release-assets.githubusercontent.com codeload.github.com pypi.org files.pythonhosted.org huggingface.co"

REPO="kaywoz/masque-ir"
BIN_DIR="$HOME/.local/bin"

# uv, pinned: version and the SHA256 of each release asset (from the
# release's own .sha256 files, checked 2026-11-23).
UV_VERSION="0.11.32"
uv_sha256() {
  case "$1" in
    x86_64-unknown-linux-gnu)  echo aab924fd522efd06f1c5f3b93a243864fc453132c94b2dc49f1371b528a4b967 ;;
    aarch64-unknown-linux-gnu) echo 4d4fa08d95b06642e5800df6a22bd71455f23f988269e18da2847971d8c0bf31 ;;
    x86_64-apple-darwin)       echo 77f5ca26c0de20e992a3677a174fe1121ee25c36f9b1434a863f75bf077a05eb ;;
    aarch64-apple-darwin)      echo ed336d0ba49db8ef89b2b41fffa372ce63bd032f22a56f001c265891aec32829 ;;
    *) return 1 ;;
  esac
}

fails=0
warns=0

say()  { printf '%-5s %-14s %s\n' "$1" "$2" "$3"; }
pass() { say PASS "$1" "$2"; }
info() { say INFO "$1" "$2"; }
warn() { say WARN "$1" "$2"; warns=$((warns + 1)); }
fail() { say FAIL "$1" "$2"; fails=$((fails + 1)); }

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }

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

# Total RAM in MiB.
ram_total_mib() {
  case "$1" in
    macos) echo $(( $(sysctl -n hw.memsize) / 1048576 )) ;;
    *)     awk '/^MemTotal:/ {printf "%d", $2 / 1024}' /proc/meminfo ;;
  esac
}

# Available RAM in MiB (Linux/WSL only; macOS has no single figure).
ram_avail_mib() {
  awk '/^MemAvailable:/ {printf "%d", $2 / 1024}' /proc/meminfo
}

# MiB as GB with one decimal.
gb() { awk -v m="$1" 'BEGIN {printf "%.1f", m / 1024}'; }

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
    total="$(ram_total_mib "$kind")"
    if [ "$total" -lt "$MIN_RAM_MIB" ]; then
      fail ram "$(gb "$total") GB total; need 8 GB or more"
    elif [ "$total" -lt "$WARN_RAM_MIB" ]; then
      warn ram "$(gb "$total") GB total; works, but the optional LLM check will be tight"
    else
      pass ram "$(gb "$total") GB total"
    fi
    if [ "$kind" != macos ]; then
      info ram-free "$(gb "$(ram_avail_mib)") GB available now"
    fi
    if [ "$kind" = wsl ] && [ "$total" -lt "$WARN_RAM_MIB" ]; then
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
    warn uv "not installed: the installer adds uv $UV_VERSION to $BIN_DIR"
  fi

  # curl (needed for the install only)
  if command -v curl >/dev/null 2>&1; then
    pass curl "present"
    for h in $NET_HOSTS; do
      if reachable "$h"; then
        pass net "$h reachable"
      else
        case "$h" in
          huggingface.co) hint="copy the models in later with --models-from DIR" ;;
          pypi.org|files.pythonhosted.org) hint="needed to build masquer; ask IT to allow it" ;;
          *)              hint="needed to download uv and masquer; ask IT to allow it" ;;
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
  fails=0
  warns=0
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
    if v="$(masquer --version 2>/dev/null)"; then
      pass masquer "$v at $(command -v masquer)"
    else
      fail masquer "$(command -v masquer) doesn't run"
    fi
  else
    fail masquer "command not found"
  fi
  echo
  echo "Result: $fails failed, $warns warnings"
  [ "$fails" -eq 0 ]
}

# --- install ---------------------------------------------------------------

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

uv_target() {
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64|Linux/amd64)   echo x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64)  echo aarch64-unknown-linux-gnu ;;
    Darwin/x86_64)              echo x86_64-apple-darwin ;;
    Darwin/arm64)               echo aarch64-apple-darwin ;;
    *) return 1 ;;
  esac
}

# Latest release tag, or empty when there is none.
latest_tag() {
  loc="$(curl -sS -o /dev/null -w '%{redirect_url}' -m 20 "https://github.com/$REPO/releases/latest" || true)"
  case "$loc" in
    */releases/tag/*) echo "${loc##*/}" ;;
    *) echo "" ;;
  esac
}

install_uv() {
  if command -v uv >/dev/null 2>&1; then
    echo "uv: $(uv --version) already installed"
    return 0
  fi
  if [ -x "$BIN_DIR/uv" ]; then
    echo "uv: found in $BIN_DIR"
    return 0
  fi
  t="$(uv_target)" || { echo "uv: no pinned build for $(uname -s)/$(uname -m)" >&2; return 1; }
  want="$(uv_sha256 "$t")"
  asset="uv-$t.tar.gz"
  url="https://github.com/astral-sh/uv/releases/download/$UV_VERSION/$asset"
  T="$(mktemp -d)"
  echo "uv: downloading $asset ($UV_VERSION)"
  curl -fsSL -m 300 -o "$T/$asset" "$url" || { echo "uv: download failed: $url" >&2; rm -rf "$T"; return 1; }
  [ -s "$T/$asset" ] || { echo "uv: download is empty" >&2; rm -rf "$T"; return 1; }
  got="$(sha256_of "$T/$asset")"
  if [ "$got" != "$want" ]; then
    echo "uv: SHA256 mismatch (got $got, want $want); nothing installed" >&2
    rm -rf "$T"
    return 1
  fi
  if ! { tar -xzf "$T/$asset" -C "$T" &&
          mkdir -p "$BIN_DIR" &&
          install -m 755 "$T/uv-$t/uv" "$BIN_DIR/uv" &&
          install -m 755 "$T/uv-$t/uvx" "$BIN_DIR/uvx"; }; then
    echo "uv: unpack failed" >&2
    rm -rf "$T"
    return 1
  fi
  rm -rf "$T"
  echo "uv: installed $("$BIN_DIR/uv" --version) to $BIN_DIR (SHA256 checked)"
}

run_install() {
  if ! run_check; then
    echo "Install stopped: fix the FAIL lines above first." >&2
    return 1
  fi
  echo
  install_uv || return 1
  uvbin="$(command -v uv 2>/dev/null || echo "$BIN_DIR/uv")"

  if [ -z "$ref" ]; then
    ref="$(latest_tag)"
    if [ -z "$ref" ]; then
      ref=main
      echo "masquer: no release yet; installing from the main branch"
    fi
  fi
  src="https://github.com/$REPO/archive/$ref.tar.gz"
  echo "masquer: installing $ref"
  UV_TOOL_BIN_DIR="$BIN_DIR" "$uvbin" tool install --force --python ">=3.11" "masquer @ $src" ||
    { echo "masquer: install failed (PyPI and GitHub must be reachable)" >&2; return 1; }

  mkdir -p "$PREFIX_DATA" "$PREFIX_CONF" && chmod 700 "$PREFIX_CONF" || return 1

  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo
       echo "Add $BIN_DIR to your PATH, then open a new shell:"
       echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.$(basename "${SHELL:-bash}")rc" ;;
  esac
  echo
  PATH="$BIN_DIR:$PATH" run_verify
}

run_dry_run() {
  echo "Dry run: an install would"
  echo "  1. run --check and stop on any FAIL"
  if command -v uv >/dev/null 2>&1; then
    echo "  2. keep the installed $(uv --version)"
  else
    echo "  2. download uv $UV_VERSION ($(uv_target 2>/dev/null || echo unsupported)) from GitHub, check its SHA256, put it in $BIN_DIR"
  fi
  echo "  3. install masquer (${ref:-latest release, else main}) with 'uv tool install' into $BIN_DIR"
  echo "  4. create $PREFIX_DATA and $PREFIX_CONF (mode 700, for the local deny-lists)"
  echo "  5. run --verify"
  echo "Nothing is changed."
}

# --- main ------------------------------------------------------------------

mode=install
ref=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check)   mode=check ;;
    --verify)  mode=verify ;;
    --dry-run) mode=dry-run ;;
    --ref)     [ $# -ge 2 ] || { echo "install.sh: --ref needs a value" >&2; exit 2; }
               ref="$2"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$mode" in
  check)   if run_check; then exit 0; else exit 1; fi ;;
  verify)  if run_verify; then exit 0; else exit 1; fi ;;
  dry-run) run_dry_run ;;
  install) if run_install; then exit 0; else exit 1; fi ;;
esac
