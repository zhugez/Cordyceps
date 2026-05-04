#!/usr/bin/env bash
# Cordyceps install script for OpenClaw + Hermes Agent runtimes.
# Auto-detects runtime, fetches latest Mycelium release from GitHub.

set -euo pipefail

RUNTIME="auto"
MYCELIUM_VERSION="latest"
SKIP_BINARY=0
LINK_MODE="copy"

usage() {
    cat <<EOF
Usage: $0 [--runtime <openclaw|hermes|auto>] [--mycelium-version <tag>] [--skip-binary] [--link]

Options:
  --runtime           Target runtime. 'auto' detects from \$HERMES_HOME / \$OPENCLAW_HOME or
                      from the presence of ~/.hermes / ~/.openclaw (default: auto).
  --mycelium-version  Mycelium release tag, e.g. v1.2.0 (default: latest).
  --skip-binary       Skip Mycelium download (assume it is already on PATH).
  --link              Symlink instead of copy (developer mode — edits propagate).
  -h, --help          Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runtime) RUNTIME="$2"; shift 2;;
        --mycelium-version) MYCELIUM_VERSION="$2"; shift 2;;
        --skip-binary) SKIP_BINARY=1; shift;;
        --link) LINK_MODE="link"; shift;;
        -h|--help) usage; exit 0;;
        *) echo "Unknown arg: $1" >&2; usage; exit 1;;
    esac
done

# ANSI helpers — honour NO_COLOR and disable when stdout is not a TTY
if [[ -z "${NO_COLOR:-}" && -t 1 ]]; then
    GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; CYAN=$'\033[0;36m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
else
    GREEN=""; RED=""; CYAN=""; YELLOW=""; NC=""
fi

log()   { printf '%s[*]%s %s\n' "$CYAN" "$NC" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$GREEN" "$NC" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$YELLOW" "$NC" "$*"; }
fail()  { printf '%s[ERROR]%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect runtime
if [[ "$RUNTIME" == "auto" ]]; then
    if [[ -n "${HERMES_HOME:-}" || -d "$HOME/.hermes" ]]; then
        RUNTIME="hermes"
    elif [[ -n "${OPENCLAW_HOME:-}" || -d "$HOME/.openclaw" ]]; then
        RUNTIME="openclaw"
    else
        fail "Cannot auto-detect runtime. Pass --runtime openclaw or --runtime hermes."
    fi
    log "Auto-detected runtime: $RUNTIME"
fi

case "$RUNTIME" in
    openclaw)
        BASE="${OPENCLAW_HOME:-$HOME/.openclaw}"
        TARGET="$BASE/skills/cordyceps"
        ;;
    hermes)
        BASE="${HERMES_HOME:-$HOME/.hermes}"
        TARGET="$BASE/skills/security/cordyceps"
        ;;
    *)
        fail "Unknown runtime: $RUNTIME (use openclaw|hermes|auto)"
        ;;
esac

log "Installing to: $TARGET"
mkdir -p "$TARGET"

# Skill assets to install. SKILL.md is REQUIRED; others are nice-to-have.
ASSETS=(SKILL.md scanner.py scan.sh README.md LICENSE pyproject.toml)
for asset in "${ASSETS[@]}"; do
    src="$SCRIPT_DIR/$asset"
    [[ -e "$src" ]] || { warn "$asset not found in $SCRIPT_DIR — skipping"; continue; }
    dst="$TARGET/$asset"
    if [[ "$LINK_MODE" == "link" ]]; then
        rm -f "$dst"
        ln -sf "$src" "$dst"
    else
        cp -f "$src" "$dst"
    fi
done
chmod +x "$TARGET/scan.sh" "$TARGET/scanner.py" 2>/dev/null || true
ok "Skill assets installed."

# Mycelium binary
if [[ "$SKIP_BINARY" == "1" ]]; then
    warn "Skipping Mycelium binary download (--skip-binary). Make sure 'mycelium' is on PATH."
else
    os_raw="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$os_raw" in
        linux*)  os="linux";;
        darwin*) os="darwin";;
        *) fail "Unsupported OS for binary download: $os_raw. Use --skip-binary and install Mycelium manually.";;
    esac
    arch_raw="$(uname -m)"
    case "$arch_raw" in
        x86_64|amd64) arch="amd64";;
        aarch64|arm64) arch="arm64";;
        *) fail "Unsupported arch: $arch_raw. Use --skip-binary.";;
    esac
    asset_pat="mycelium-${os}-${arch}"

    if [[ "$MYCELIUM_VERSION" == "latest" ]]; then
        api_url="https://api.github.com/repos/zhugez/Mycelium/releases/latest"
    else
        api_url="https://api.github.com/repos/zhugez/Mycelium/releases/tags/${MYCELIUM_VERSION}"
    fi

    log "Querying Mycelium release: $api_url"
    json=$(curl -fsSL -H "User-Agent: cordyceps-installer" "$api_url") \
        || fail "Failed to fetch release metadata. Check network or GitHub rate limit."

    download_url=$(printf '%s' "$json" \
        | grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' \
        | grep -- "$asset_pat" \
        | head -n1 \
        | sed -E 's/.*"(https:[^"]+)".*/\1/' || true)

    if [[ -z "$download_url" ]]; then
        echo "Available assets:" >&2
        printf '%s' "$json" \
            | grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' \
            | sed -E 's/.*"([^"]+)".*/  - \1/' >&2 || true
        fail "No asset matching '$asset_pat' in release."
    fi

    bin_path="$TARGET/mycelium"
    log "Downloading $download_url"
    curl -fsSL -H "User-Agent: cordyceps-installer" "$download_url" -o "$bin_path"
    chmod +x "$bin_path"
    ok "Mycelium installed: $bin_path"

    # Mirror to BASE/tools/cordyceps for OpenClaw convention
    tools_dir="$BASE/tools/cordyceps"
    mkdir -p "$tools_dir"
    cp -f "$bin_path" "$tools_dir/mycelium"
    chmod +x "$tools_dir/mycelium"
fi

ok "Cordyceps installed for $RUNTIME runtime."
case "$RUNTIME" in
    openclaw)
        echo
        log "Try it:  openclaw run cordyceps   # or invoke 'Cordyceps' from your OpenClaw client"
        ;;
    hermes)
        echo
        log "Try it:  hermes /cordyceps         # in interactive Hermes session"
        log "         hermes skills list | grep cordyceps"
        ;;
esac
