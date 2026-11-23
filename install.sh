#!/usr/bin/env bash
# install.sh — installer for masquer (repo masque-ir).
#
# Modes:
#   (none)      check prerequisites, then install uv (if missing) and masquer
#   --check     check prerequisites only; changes nothing
#   --dry-run   show what an install would do; changes nothing
#   --verify    check an existing install
#   --ref REF   install this tag or branch instead of the latest release
#   --wheel F   install masquer from a local wheel file (no PyPI, no GitHub)
#   --prefer-wheel  use the release wheel even when PyPI is reachable
#   --with-ner  also install the name-detection stage (gliner, CPU torch,
#               the pinned GLiNER model, ~1.2 GB in total)
#   --models-from DIR  take the model files from DIR instead of Hugging Face
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
MODEL_DIR="$PREFIX_DATA/models/gliner-pii"

# Thresholds. Models: GLiNER ~1 GB + Qwen3.5 4B Q4 ~3 GB, plus headroom.
# RAM in MiB with 0.5 GiB slack: the kernel reserves memory, so an 8 GB
# machine or WSL VM reports roughly 7.6-7.9 GiB in MemTotal.
MIN_RAM_MIB=7680    # "8 GB"
WARN_RAM_MIB=11776  # "12 GB"
MIN_DISK_GB=6

# Hosts the install needs (not masquer itself, which never uses the network).
NET_HOSTS="github.com release-assets.githubusercontent.com codeload.github.com pypi.org files.pythonhosted.org huggingface.co"

REPO="kaywoz/masque-ir"
NER_HOSTS="download.pytorch.org download-r2.pytorch.org huggingface.co us.aws.cdn.hf.co"
# Name-detection model, pinned: repository, revision and SHA256 per file.
MODEL_REPO="knowledgator/gliner-pii-edge-v1.0"
MODEL_REV="9b7f39b0a2da971a5beea78d35f1539d4009c891"
MODEL_FILES="gliner_config.json 77e6b57335c4bfd461e9041682196dd6c373a0b09bbd9269ef9e95b807915340
tokenizer.json 84b3a9b18f04a0ccd03b72d9f871b7e0bec40fd7021ef50bc30a7c3693c11205
tokenizer_config.json 3398f6d1ad4b4c4f9874d390d060a75c58cad5e5ce9b22841b3e40643b4ada27
special_tokens_map.json ea97ecdbcc73713039d8d64dbb05e3689495c96657fbd9a18f5bed381be81049
pytorch_model.bin 0160706fa5d034410175cc53808419d975658e12f1cac1a916fbde8155155add"
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

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }

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

# curl exit code for a host: 0 ok; 35/51/58/60/77 = TLS (often a corporate
# proxy inspecting TLS with a CA this system doesn't trust); else unreachable.
probe() {
  if curl -sS -o /dev/null -m 10 -I "https://$1" >/dev/null 2>&1; then echo 0; else echo $?; fi
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

  # Python for masquer (3.11+). Without one, uv downloads a managed Python
  # from GitHub's release host.
  py=""
  for c in python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 &&
       "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      py="$c"
      break
    fi
  done
  if [ -n "$py" ]; then
    pass python "$("$py" --version 2>&1) ($(command -v "$py"))"
  else
    warn python "no Python 3.11+: uv downloads one from release-assets.githubusercontent.com"
  fi

  # curl (needed for the install only)
  if command -v curl >/dev/null 2>&1; then
    pass curl "present"
    hosts="$NET_HOSTS"
    [ "$with_ner" = yes ] && hosts="$hosts $NER_HOSTS"
    for h in $hosts; do
      rc="$(probe "$h")"
      if [ "$rc" = 0 ]; then
        pass net "$h reachable"
        continue
      fi
      case "$h" in
        huggingface.co|us.aws.cdn.hf.co) hint="copy the model in with --models-from DIR" ;;
        download.pytorch.org|download-r2.pytorch.org) hint="needed for CPU torch (--with-ner); ask IT to allow it" ;;
        pypi.org|files.pythonhosted.org) hint="needed for the uv fallback and source builds" ;;
        release-assets.githubusercontent.com) hint="uv falls back to PyPI; release wheels and managed Python need it" ;;
        *)              hint="needed to download masquer" ;;
      esac
      case "$rc" in
        56)             warn net "$h refused by a proxy: $hint" ;;
        35|51|58|60|77) warn net "$h: TLS certificate not trusted (likely TLS inspection; corporate CA missing here): $hint" ;;
        *)              warn net "$h not reachable: $hint" ;;
      esac
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
  if [ -d "$MODEL_DIR" ]; then
    bad=0
    while read -r name want; do
      [ -n "$name" ] || continue
      if [ ! -f "$MODEL_DIR/$name" ] || [ "$(sha256_of "$MODEL_DIR/$name")" != "$want" ]; then
        bad=$((bad + 1))
      fi
    done <<EOF_MODEL
$MODEL_FILES
EOF_MODEL
    if [ "$bad" -eq 0 ]; then
      pass model "$MODEL_REPO ($MODEL_REV) in $MODEL_DIR, SHA256 ok"
    else
      fail model "$bad model file(s) missing or changed in $MODEL_DIR; re-run with --with-ner"
    fi
  else
    info model "name-detection model not installed (install with --with-ner)"
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
  if ! curl -fsSL -m 300 -o "$T/$asset" "$url"; then
    rm -rf "$T"
    echo "uv: GitHub download failed; trying the uv wheel from PyPI"
    install_uv_from_pypi "$t"
    return $?
  fi
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

# uv is also published on PyPI as wheels that carry the same binary. Used
# when GitHub's release download host is blocked or TLS-inspected.
uv_wheel() {
  case "$1" in
    x86_64-unknown-linux-gnu)  echo "uv-$UV_VERSION-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl 3da76cd4e2697de30928b8a8524bd39183ac1e08cb7e72833807c022b7cba6c4" ;;
    aarch64-unknown-linux-gnu) echo "uv-$UV_VERSION-py3-none-manylinux_2_28_aarch64.whl be0799f1ad70c755d10de5aaf46af94199d4f16a992f90278f2662350cd3f4fe" ;;
    x86_64-apple-darwin)       echo "uv-$UV_VERSION-py3-none-macosx_10_12_x86_64.whl c82954b1bd507e767b1d996c2865ea3eb7d464a479ec0e4d60f0b8e2e07dee45" ;;
    aarch64-apple-darwin)      echo "uv-$UV_VERSION-py3-none-macosx_11_0_arm64.whl 2a56d1abf16337350e878b2c869b256b8448ecc4a722b98f8d41e1b3680a587b" ;;
    *) return 1 ;;
  esac
}

# Extract one member of a zip (a wheel) to a file.
unzip_member() {
  if command -v unzip >/dev/null 2>&1; then
    unzip -p "$1" "$2" > "$3"
  elif command -v python3 >/dev/null 2>&1; then
    python3 -I -c 'import sys, zipfile; open(sys.argv[3], "wb").write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]))' "$1" "$2" "$3"
  elif command -v bsdtar >/dev/null 2>&1; then
    bsdtar -xOf "$1" "$2" > "$3"
  else
    return 1
  fi
}

install_uv_from_pypi() {
  pair="$(uv_wheel "$1" || true)"
  whl="${pair%% *}"
  want="${pair##* }"
  [ -n "$whl" ] || { echo "uv: no pinned PyPI wheel for $1" >&2; return 1; }
  T="$(mktemp -d)"
  index="$(curl -fsSL -m 60 https://pypi.org/simple/uv/ || true)"
  url="$(printf '%s\n' "$index" | grep -o "https://[^\"#]*/$whl" | head -1 || true)"
  if [ -z "$url" ]; then
    echo "uv: $whl not found on PyPI (pypi.org blocked?)" >&2
    rm -rf "$T"
    return 1
  fi
  if ! curl -fsSL -m 300 -o "$T/$whl" "$url" || [ ! -s "$T/$whl" ]; then
    echo "uv: download failed: $url" >&2
    rm -rf "$T"
    return 1
  fi
  got="$(sha256_of "$T/$whl")"
  if [ "$got" != "$want" ]; then
    echo "uv: SHA256 mismatch for $whl (got $got, want $want); nothing installed" >&2
    rm -rf "$T"
    return 1
  fi
  if ! { unzip_member "$T/$whl" "uv-$UV_VERSION.data/scripts/uv" "$T/uv" &&
          unzip_member "$T/$whl" "uv-$UV_VERSION.data/scripts/uvx" "$T/uvx" &&
          mkdir -p "$BIN_DIR" &&
          install -m 755 "$T/uv" "$BIN_DIR/uv" &&
          install -m 755 "$T/uvx" "$BIN_DIR/uvx"; }; then
    echo "uv: unpack failed (needs unzip, python3 or bsdtar)" >&2
    rm -rf "$T"
    return 1
  fi
  rm -rf "$T"
  echo "uv: installed $("$BIN_DIR/uv" --version) to $BIN_DIR from PyPI (SHA256 checked)"
}

pypi_reachable() {
  reachable pypi.org && reachable files.pythonhosted.org
}

# Download a release's wheel and check it against the release's SHA256SUMS.
# Prints the local wheel path. The wheel is pure Python (py3-none-any), so the
# same file serves Linux, WSL2 and macOS.
fetch_release_wheel() {
  tag="$1"
  ver="${tag#v}"
  whl="masquer-$ver-py3-none-any.whl"
  base="${MASQUER_RELEASE_BASE:-https://github.com/$REPO/releases/download}/$tag"
  W="$(mktemp -d)"
  if ! curl -fsSL -m 120 -o "$W/$whl" "$base/$whl" ||
     ! curl -fsSL -m 60 -o "$W/SHA256SUMS" "$base/SHA256SUMS"; then
    echo "masquer: release $tag has no $whl or SHA256SUMS" >&2
    rm -rf "$W"
    return 1
  fi
  [ -s "$W/$whl" ] || { echo "masquer: $whl is empty" >&2; rm -rf "$W"; return 1; }
  want="$(awk -v f="$whl" '$2 == f || $2 == "*"f || $2 == "dist/"f {print $1}' "$W/SHA256SUMS")"
  got="$(sha256_of "$W/$whl")"
  if [ -z "$want" ] || [ "$got" != "$want" ]; then
    echo "masquer: SHA256 mismatch for $whl (got $got, want ${want:-none}); nothing installed" >&2
    rm -rf "$W"
    return 1
  fi
  echo "$W/$whl"
}

# Model files into MODEL_DIR, each checked against its pinned SHA256; files
# already in place with the right hash are kept. From --models-from DIR when
# given, else from Hugging Face at the pinned revision.
install_model() {
  mkdir -p "$MODEL_DIR" || return 1
  echo "$MODEL_FILES" | while read -r name want; do
    [ -n "$name" ] || continue
    dest="$MODEL_DIR/$name"
    if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$want" ]; then
      echo "model: $name ok"
      continue
    fi
    T="$(mktemp)"
    if [ -n "$models_from" ]; then
      cp "$models_from/$name" "$T" || { echo "model: $name missing in $models_from" >&2; rm -f "$T"; exit 1; }
    else
      curl -fsSL -m 900 -o "$T" "https://huggingface.co/$MODEL_REPO/resolve/$MODEL_REV/$name" ||
        { echo "model: download failed: $name (use --models-from DIR)" >&2; rm -f "$T"; exit 1; }
    fi
    got="$(sha256_of "$T")"
    if [ ! -s "$T" ] || [ "$got" != "$want" ]; then
      echo "model: SHA256 mismatch for $name (got $got, want $want); not installed" >&2
      rm -f "$T"
      exit 1
    fi
    install -m 644 "$T" "$dest" && rm -f "$T" && echo "model: $name installed (SHA256 checked)"
  done
}

run_install() {
  if ! run_check; then
    echo "Install stopped: fix the FAIL lines above first." >&2
    return 1
  fi
  echo
  install_uv || return 1
  extra=""
  noindex="--no-index"
  pyreq=">=3.11"
  if [ "$with_ner" = yes ]; then
    extra="[ner]"
    noindex=""  # gliner and CPU torch come from PyPI and download.pytorch.org
    # CPU-only torch: the default Linux build pulls several GB of CUDA libraries.
    # (pyproject's tool.uv.sources isn't applied to URL installs; this is.)
    export UV_TORCH_BACKEND=cpu
    pyreq=">=3.11,<3.14"  # torch.jit warns it may break on 3.14+
  fi
  uvbin="$(command -v uv 2>/dev/null || echo "$BIN_DIR/uv")"

  if [ -n "$wheel" ]; then
    # Local wheel: no index, no source build.
    [ -s "$wheel" ] || { echo "masquer: wheel $wheel not found or empty" >&2; return 1; }
    echo "masquer: installing local wheel $(basename "$wheel")"
    UV_TOOL_BIN_DIR="$BIN_DIR" "$uvbin" tool install --force $noindex --python "$pyreq" "masquer$extra @ file://$(cd "$(dirname "$wheel")" && pwd)/$(basename "$wheel")" ||
      { echo "masquer: install from wheel failed" >&2; return 1; }
  else
    [ -n "$ref" ] || ref="$(latest_tag)"
    use_wheel=no
    if [ -n "$ref" ] && { [ "$prefer_wheel" = yes ] || ! pypi_reachable; }; then
      case "$ref" in v[0-9]*) use_wheel=yes ;; esac
    fi
    if [ "$use_wheel" = yes ]; then
      echo "masquer: installing the $ref release wheel (no PyPI needed)"
      w="$(fetch_release_wheel "$ref")" || return 1
      UV_TOOL_BIN_DIR="$BIN_DIR" "$uvbin" tool install --force $noindex --python "$pyreq" "masquer$extra @ file://$w" ||
        { echo "masquer: install from wheel failed" >&2; rm -rf "$(dirname "$w")"; return 1; }
      rm -rf "$(dirname "$w")"
    else
      if ! pypi_reachable; then
        echo "masquer: PyPI isn't reachable and there is no release wheel for '${ref:-main}';" >&2
        echo "  copy a release wheel here and run: bash install.sh --wheel FILE" >&2
        return 1
      fi
      if [ -z "$ref" ]; then
        ref=main
        echo "masquer: no release yet; installing from the main branch"
      fi
      echo "masquer: building and installing $ref (source, needs PyPI)"
      UV_TOOL_BIN_DIR="$BIN_DIR" "$uvbin" tool install --force --python "$pyreq" \
        "masquer$extra @ https://github.com/$REPO/archive/$ref.tar.gz" ||
        { echo "masquer: install failed (PyPI and GitHub must be reachable)" >&2; return 1; }
    fi
  fi

  mkdir -p "$PREFIX_DATA" "$PREFIX_CONF" && chmod 700 "$PREFIX_CONF" || return 1
  if [ "$with_ner" = yes ]; then
    install_model || return 1
  fi

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
  if [ -n "$wheel" ]; then
    echo "  3. install masquer from the local wheel $wheel (no index) into $BIN_DIR"
  else
    echo "  3. install masquer (${ref:-latest release, else main}) into $BIN_DIR:"
    echo "     the release wheel (SHA256 from SHA256SUMS) when PyPI is blocked or --prefer-wheel,"
    echo "     otherwise a source build from GitHub (needs PyPI)"
  fi
  echo "  4. create $PREFIX_DATA and $PREFIX_CONF (mode 700, for the local deny-lists)"
  echo "  5. run --verify"
  echo "Nothing is changed."
}

# --- main ------------------------------------------------------------------

mode=install
ref=""
wheel=""
prefer_wheel=no
with_ner=no
models_from=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check)   mode=check ;;
    --verify)  mode=verify ;;
    --dry-run) mode=dry-run ;;
    --ref)     [ $# -ge 2 ] || { echo "install.sh: --ref needs a value" >&2; exit 2; }
               ref="$2"; shift ;;
    --wheel)   [ $# -ge 2 ] || { echo "install.sh: --wheel needs a file" >&2; exit 2; }
               wheel="$2"; shift ;;
    --prefer-wheel) prefer_wheel=yes ;;
    --with-ner) with_ner=yes ;;
    --models-from) [ $# -ge 2 ] || { echo "install.sh: --models-from needs a folder" >&2; exit 2; }
                   models_from="$2"; with_ner=yes; shift ;;
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
