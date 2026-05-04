#!/usr/bin/env bash
# Cordyceps - WordPress Plugin Vulnerability Scanner (Bash quick-scan)
# Patchstack-aligned heuristics; for deeper analysis use scanner.py.

set -euo pipefail

# ---------- Colour handling -----------------------------------------------------
# Respect NO_COLOR (https://no-color.org) and only emit ANSI when stdout is a TTY.
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
    RED=''; YELLOW=''; GREEN=''; CYAN=''; NC=''
else
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    NC='\033[0m'
fi

# ---------- Defaults -----------------------------------------------------------
MIN_ACTIVE=${MIN_ACTIVE:-10000}
PAGES=${PAGES:-5}
PER_PAGE=${PER_PAGE:-20}
WORKERS=${WORKERS:-5}
OUTPUT_DIR=${OUTPUT_DIR:-wp_zips}
EXTRACT_DIR=${EXTRACT_DIR:-wp_extracted}
CSV_PATH=${CSV_PATH:-plugins.csv}
REPORT_FILE=${REPORT_FILE:-vuln_report.md}
HEAD_LIMIT=${HEAD_LIMIT:-100}
MYCELIUM_BIN=""
USE_GREP=0

EXCLUDE_DIRS=(vendor node_modules tests test __tests__ .git .svn .hg dist build cache)

# ---------- Helpers ------------------------------------------------------------
log_info()  { printf '%b\n' "${CYAN}[*] $*${NC}"; }
log_warn()  { printf '%b\n' "${YELLOW}[!] $*${NC}" >&2; }
log_ok()    { printf '%b\n' "${GREEN}[+] $*${NC}"; }
log_err()   { printf '%b\n' "${RED}[ERROR] $*${NC}" >&2; }

find_mycelium() {
    local home="${HOME:-$USERPROFILE}"
    local candidates=(
        "${CORDYCEPS_MYCELIUM:-}"
        "mycelium"
        "mycelium.exe"
        "./mycelium"
        "./mycelium.exe"
        "$home/.openclaw/tools/cordyceps/mycelium"
        "$home/.openclaw/tools/cordyceps/mycelium.exe"
        "$home/.openclaw/skills/cordyceps/mycelium"
        "$home/.openclaw/skills/cordyceps/mycelium.exe"
        "$home/.openclaw/skills/cordyceps/mycelium-linux-amd64"
        "$home/.openclaw/skills/cordyceps/mycelium-windows-amd64.exe"
        "$home/.hermes/tools/cordyceps/mycelium"
        "$home/.hermes/tools/cordyceps/mycelium.exe"
        "$home/.hermes/skills/security/cordyceps/mycelium"
        "$home/.hermes/skills/security/cordyceps/mycelium.exe"
        "$home/.hermes/skills/security/cordyceps/mycelium-linux-amd64"
        "$home/.hermes/skills/security/cordyceps/mycelium-windows-amd64.exe"
        "/tmp/openclaw-skill/mycelium"
        "/tmp/openclaw-skill/mycelium.exe"
    )
    for candidate in "${candidates[@]}"; do
        [ -z "$candidate" ] && continue
        if command -v "$candidate" &>/dev/null || [ -x "$candidate" ]; then
            MYCELIUM_BIN="$candidate"
            return 0
        fi
    done
    log_err "Mycelium binary not found."
    cat >&2 <<EOF
Install via:    bash install.sh                (or .\\install.ps1 on Windows)
Or fetch:       https://github.com/zhugez/Mycelium/releases/latest
EOF
    exit 1
}

# Run a regex against PHP files under a directory. Abstracts rg/grep so the
# fallback path actually works (the previous implementation passed --type php
# to grep and crashed).
search_php() {
    local pattern="$1"
    local root="$2"
    if [ "$USE_GREP" -eq 1 ]; then
        local args=(-rnE --include='*.php')
        for d in "${EXCLUDE_DIRS[@]}"; do
            args+=(--exclude-dir="$d")
        done
        grep "${args[@]}" "$pattern" "$root" 2>/dev/null || true
    else
        # Use --iglob with **/<dir>/** so patterns match path components
        # but stay relative to the working directory; cd into root so the
        # search root itself isn't filtered out by directory-name globs.
        # rg uses extended regex by default; -E in rg means encoding.
        local args=(-n --type php)
        for d in "${EXCLUDE_DIRS[@]}"; do
            args+=(--glob "!**/${d}/**")
        done
        ( cd "$root" 2>/dev/null && rg "${args[@]}" "$pattern" . 2>/dev/null \
            | sed -e "s|^\./|${root%/}/|" -e "s|^\.\\\\|${root%/}/|" ) || true
    fi
}

# Append search hits to the report; warn when the truncation cap kicked in.
emit_section() {
    local label="$1"
    local pattern="$2"
    local count_var="$3"
    local raw
    raw=$(search_php "$pattern" "$EXTRACT_DIR")
    local total
    total=$(printf '%s\n' "$raw" | grep -c . || true)
    local shown="$raw"
    if [ "$total" -gt "$HEAD_LIMIT" ]; then
        shown=$(printf '%s\n' "$raw" | head -"$HEAD_LIMIT")
        log_warn "$label: truncated to first $HEAD_LIMIT of $total matches"
    fi
    if [ -n "$shown" ]; then
        while IFS= read -r line; do
            printf -- '- `%s`\n' "$line" >> "$REPORT_FILE"
        done <<< "$shown"
    fi
    eval "$count_var=$total"
}

# ---------- Phase 1: Download ---------------------------------------------------
download_plugins() {
    log_info "Phase 1: Downloading WordPress plugins with ${MIN_ACTIVE}+ active installs..."
    find_mycelium
    log_ok "Using Mycelium at: ${MYCELIUM_BIN}"

    "$MYCELIUM_BIN" \
        --min-active "$MIN_ACTIVE" \
        --pages "$PAGES" \
        --per-page "$PER_PAGE" \
        --workers "$WORKERS" \
        --output-dir "$OUTPUT_DIR" \
        --extract \
        --extract-dir "$EXTRACT_DIR" \
        --csv-path "$CSV_PATH"

    log_ok "Download complete. Plugins extracted to: ${EXTRACT_DIR}"
}

# ---------- Phase 2: Scan -------------------------------------------------------
scan_vulnerabilities() {
    log_info "Phase 2: Scanning for vulnerabilities..."

    if [ ! -d "$EXTRACT_DIR" ]; then
        log_err "Extract directory not found: ${EXTRACT_DIR}"
        exit 1
    fi

    if ! command -v rg &>/dev/null; then
        log_warn "ripgrep (rg) not found, falling back to grep."
        USE_GREP=1
    fi

    {
        printf '# WordPress Plugin Vulnerability Scan Report\n\n'
        printf '**Scanner:** cordyceps (Patchstack-based)\n'
        printf '**Knowledge Base:** https://patchstack.com/academy/wordpress/vulnerabilities/\n'
        printf '**Date:** %s\n\n' "$(date -u +"%Y-%m-%d %H:%M UTC")"
        printf -- '---\n\n'
    } > "$REPORT_FILE"

    local total_findings=0
    local sqli_count=0 xss_count=0 upload_count=0 bac_count=0 poi_count=0
    local rce_count=0 ssrf_count=0 privesc_count=0 fileop_count=0

    log_info "Scanning for SQL Injection..."
    printf '## SQL Injection (SQLi)\n\n' >> "$REPORT_FILE"
    emit_section "SQLi (wp_unslash)" 'wp_unslash.*\$_(GET|POST|REQUEST|COOKIE)' sqli_a
    emit_section "SQLi (wpdb)" '\$wpdb->(query|get_var|get_row|get_col|get_results).*\$_(GET|POST|REQUEST)' sqli_b
    sqli_count=$((sqli_a + sqli_b))
    printf '\n**Total SQLi indicators:** %s\n\n' "$sqli_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + sqli_count))

    log_info "Scanning for XSS..."
    printf '## Cross-Site Scripting (XSS)\n\n' >> "$REPORT_FILE"
    emit_section "XSS" 'echo.*\$_(GET|POST|REQUEST|SERVER)' xss_count
    printf '\n**Total XSS indicators:** %s\n\n' "$xss_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + xss_count))

    log_info "Scanning for File Upload vulnerabilities..."
    printf '## Arbitrary File Upload\n\n' >> "$REPORT_FILE"
    emit_section "File Upload" 'move_uploaded_file\(|test_type.*false' upload_count
    printf '\n**Total File Upload indicators:** %s\n\n' "$upload_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + upload_count))

    log_info "Scanning for Broken Access Control..."
    printf '## Broken Access Control\n\n' >> "$REPORT_FILE"
    emit_section "BAC" '__return_true.*permission_callback|permission_callback.*__return_true' bac_count
    printf '\n**Total BAC indicators:** %s\n\n' "$bac_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + bac_count))

    log_info "Scanning for PHP Object Injection..."
    printf '## PHP Object Injection\n\n' >> "$REPORT_FILE"
    emit_section "POI" 'unserialize\(.*\$_(GET|POST|REQUEST|COOKIE)' poi_count
    printf '\n**Total POI indicators:** %s\n\n' "$poi_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + poi_count))

    log_info "Scanning for RCE..."
    printf '## Remote Code Execution (RCE)\n\n' >> "$REPORT_FILE"
    emit_section "RCE" '(system|exec|shell_exec|passthru|proc_open|eval)\s*\(.*\$_(GET|POST|REQUEST)' rce_count
    printf '\n**Total RCE indicators:** %s\n\n' "$rce_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + rce_count))

    log_info "Scanning for SSRF..."
    printf '## Server-Side Request Forgery (SSRF)\n\n' >> "$REPORT_FILE"
    emit_section "SSRF" 'wp_remote_(get|post|head|request)\(.*\$_(GET|POST|REQUEST)' ssrf_count
    printf '\n**Total SSRF indicators:** %s\n\n' "$ssrf_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + ssrf_count))

    log_info "Scanning for Privilege Escalation..."
    printf '## Privilege Escalation\n\n' >> "$REPORT_FILE"
    emit_section "PrivEsc" 'wp_set_auth_cookie\(|wp_set_current_user\(.*\$_(GET|POST|REQUEST)' privesc_count
    printf '\n**Total Priv Esc indicators:** %s\n\n' "$privesc_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + privesc_count))

    log_info "Scanning for Arbitrary File Read/Delete..."
    printf '## Arbitrary File Read/Delete\n\n' >> "$REPORT_FILE"
    emit_section "FileOp" '(file_get_contents|readfile|unlink|highlight_file)\(.*\$_(GET|POST|REQUEST)' fileop_count
    printf '\n**Total File Read/Delete indicators:** %s\n\n' "$fileop_count" >> "$REPORT_FILE"
    total_findings=$((total_findings + fileop_count))

    {
        printf -- '\n---\n\n## Summary\n\n'
        printf '| Category | Findings |\n|----------|----------|\n'
        printf '| SQL Injection | %s |\n' "$sqli_count"
        printf '| XSS | %s |\n' "$xss_count"
        printf '| File Upload | %s |\n' "$upload_count"
        printf '| Broken Access Control | %s |\n' "$bac_count"
        printf '| PHP Object Injection | %s |\n' "$poi_count"
        printf '| RCE | %s |\n' "$rce_count"
        printf '| SSRF | %s |\n' "$ssrf_count"
        printf '| Privilege Escalation | %s |\n' "$privesc_count"
        printf '| File Read/Delete | %s |\n' "$fileop_count"
        printf '| **TOTAL** | **%s** |\n\n' "$total_findings"
        printf '> These are INDICATORS that need manual verification. Not all findings are true positives.\n'
    } >> "$REPORT_FILE"

    echo
    log_ok "Scan complete!"
    log_info "Total potential vulnerability indicators: ${total_findings}"
    log_info "Report saved to: ${REPORT_FILE}"
}

# ---------- Main ---------------------------------------------------------------
case "${1:-all}" in
    download)
        download_plugins
        ;;
    scan)
        scan_vulnerabilities
        ;;
    all)
        download_plugins
        scan_vulnerabilities
        ;;
    -h|--help|help|*)
        cat <<EOF
Usage: $0 [download|scan|all]

Subcommands:
  download    Harvest plugins via Mycelium.
  scan        Scan an already-extracted directory.
  all         Run download then scan.

Environment variables:
  MIN_ACTIVE      Minimum active installs (default: 10000)
  PAGES           Number of API pages (default: 5)
  PER_PAGE        Plugins per page (default: 20)
  WORKERS         Download workers (default: 5)
  OUTPUT_DIR      Zip output dir (default: wp_zips)
  EXTRACT_DIR     Extract dir (default: wp_extracted)
  CSV_PATH        CSV report path (default: plugins.csv)
  REPORT_FILE     Markdown report path (default: vuln_report.md)
  HEAD_LIMIT      Max matches per pattern (default: 100)
  NO_COLOR        Disable ANSI colours (any non-empty value)
  CORDYCEPS_MYCELIUM  Explicit path to the mycelium binary
EOF
        [ "${1:-all}" = "-h" ] || [ "${1:-all}" = "--help" ] || [ "${1:-all}" = "help" ] || exit 1
        exit 0
        ;;
esac
