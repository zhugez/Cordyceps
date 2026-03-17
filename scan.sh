#!/usr/bin/env bash
# WordPress Vulnerability Scanner - Automated Scanning Script
# Based on Patchstack Academy knowledge base
# Uses Mycelium to download plugins and rg/grep for pattern scanning

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
MIN_ACTIVE=${MIN_ACTIVE:-10000}
PAGES=${PAGES:-5}
PER_PAGE=${PER_PAGE:-20}
WORKERS=${WORKERS:-5}
OUTPUT_DIR=${OUTPUT_DIR:-wp_zips}
EXTRACT_DIR=${EXTRACT_DIR:-wp_extracted}
CSV_PATH=${CSV_PATH:-plugins.csv}
REPORT_FILE=${REPORT_FILE:-vuln_report.md}
MYCELIUM_BIN=""

# Find Mycelium binary
find_mycelium() {
    for candidate in \
        "mycelium" \
        "mycelium.exe" \
        "./mycelium" \
        "./mycelium.exe" \
        "$HOME/.openclaw/tools/wp-vuln-scanner/mycelium" \
        "$HOME/.openclaw/tools/wp-vuln-scanner/mycelium.exe" \
        "/tmp/openclaw-skill/mycelium" \
        "/tmp/openclaw-skill/mycelium.exe"; do
        if command -v "$candidate" &>/dev/null || [ -x "$candidate" ]; then
            MYCELIUM_BIN="$candidate"
            return 0
        fi
    done
    echo -e "${RED}[ERROR] Mycelium binary not found!${NC}"
    echo "Download from: https://github.com/zhugez/Mycelium/releases/download/v1.0.0/"
    exit 1
}

# Phase 1: Download plugins
download_plugins() {
    echo -e "${CYAN}[*] Phase 1: Downloading WordPress plugins with ${MIN_ACTIVE}+ active installs...${NC}"
    find_mycelium
    echo -e "${GREEN}[+] Using Mycelium at: ${MYCELIUM_BIN}${NC}"

    "$MYCELIUM_BIN" \
        --min-active "$MIN_ACTIVE" \
        --pages "$PAGES" \
        --per-page "$PER_PAGE" \
        --workers "$WORKERS" \
        --output-dir "$OUTPUT_DIR" \
        --extract \
        --extract-dir "$EXTRACT_DIR" \
        --csv-path "$CSV_PATH"

    echo -e "${GREEN}[+] Download complete. Plugins extracted to: ${EXTRACT_DIR}${NC}"
}

# Phase 2: Scan for vulnerabilities
scan_vulnerabilities() {
    echo -e "${CYAN}[*] Phase 2: Scanning for vulnerabilities...${NC}"

    if [ ! -d "$EXTRACT_DIR" ]; then
        echo -e "${RED}[ERROR] Extract directory not found: ${EXTRACT_DIR}${NC}"
        exit 1
    fi

    local RG="rg"
    if ! command -v rg &>/dev/null; then
        echo -e "${YELLOW}[!] ripgrep (rg) not found, falling back to grep${NC}"
        RG="grep -rn"
    fi

    # Initialize report
    cat > "$REPORT_FILE" << 'HEADER'
# WordPress Plugin Vulnerability Scan Report

**Scanner:** wp-vuln-scanner (Patchstack-based)
**Knowledge Base:** https://patchstack.com/academy/wordpress/vulnerabilities/
HEADER
    echo "**Date:** $(date -u +"%Y-%m-%d %H:%M UTC")" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local total_findings=0

    # 1. SQL Injection
    echo -e "${YELLOW}[~] Scanning for SQL Injection...${NC}"
    echo "## 🔴 SQL Injection (SQLi)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local sqli_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((sqli_count++)) || true
    done < <($RG -n 'wp_unslash.*\$_(GET|POST|REQUEST|COOKIE)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -100 || true)

    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((sqli_count++)) || true
    done < <($RG -n '\$wpdb->(query|get_var|get_row|get_col|get_results).*\$_(GET|POST|REQUEST)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -100 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total SQLi indicators:** $sqli_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + sqli_count))

    # 2. Cross-Site Scripting (XSS)
    echo -e "${YELLOW}[~] Scanning for XSS...${NC}"
    echo "## 🟠 Cross-Site Scripting (XSS)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local xss_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((xss_count++)) || true
    done < <($RG -n 'echo.*\$_(GET|POST|REQUEST|SERVER)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -100 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total XSS indicators:** $xss_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + xss_count))

    # 3. Arbitrary File Upload
    echo -e "${YELLOW}[~] Scanning for File Upload vulnerabilities...${NC}"
    echo "## 🔴 Arbitrary File Upload" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local upload_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((upload_count++)) || true
    done < <($RG -n 'move_uploaded_file\(|test_type.*false' "$EXTRACT_DIR/" --type php 2>/dev/null | head -100 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total File Upload indicators:** $upload_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + upload_count))

    # 4. Broken Access Control
    echo -e "${YELLOW}[~] Scanning for Broken Access Control...${NC}"
    echo "## 🟠 Broken Access Control" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local bac_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((bac_count++)) || true
    done < <($RG -n '__return_true.*permission_callback|permission_callback.*__return_true' "$EXTRACT_DIR/" --type php 2>/dev/null | head -100 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total BAC indicators:** $bac_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + bac_count))

    # 5. PHP Object Injection
    echo -e "${YELLOW}[~] Scanning for PHP Object Injection...${NC}"
    echo "## 🔴 PHP Object Injection" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local poi_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((poi_count++)) || true
    done < <($RG -n 'unserialize\(.*\$_(GET|POST|REQUEST|COOKIE)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -50 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total POI indicators:** $poi_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + poi_count))

    # 6. Remote Code Execution
    echo -e "${YELLOW}[~] Scanning for RCE...${NC}"
    echo "## 🔴 Remote Code Execution (RCE)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local rce_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((rce_count++)) || true
    done < <($RG -n '(system|exec|shell_exec|passthru|proc_open|eval)\s*\(.*\$_(GET|POST|REQUEST)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -50 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total RCE indicators:** $rce_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + rce_count))

    # 7. SSRF
    echo -e "${YELLOW}[~] Scanning for SSRF...${NC}"
    echo "## 🟠 Server-Side Request Forgery (SSRF)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local ssrf_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((ssrf_count++)) || true
    done < <($RG -n 'wp_remote_(get|post|head|request)\(.*\$_(GET|POST|REQUEST)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -50 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total SSRF indicators:** $ssrf_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + ssrf_count))

    # 8. Privilege Escalation
    echo -e "${YELLOW}[~] Scanning for Privilege Escalation...${NC}"
    echo "## 🔴 Privilege Escalation" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local privesc_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((privesc_count++)) || true
    done < <($RG -n 'wp_set_auth_cookie\(|wp_set_current_user\(.*\$_(GET|POST|REQUEST)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -50 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total Priv Esc indicators:** $privesc_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + privesc_count))

    # 9. File Read/Delete
    echo -e "${YELLOW}[~] Scanning for Arbitrary File Read/Delete...${NC}"
    echo "## 🟠 Arbitrary File Read/Delete" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    local fileop_count=0
    while IFS= read -r line; do
        echo "- \`$line\`" >> "$REPORT_FILE"
        ((fileop_count++)) || true
    done < <($RG -n '(file_get_contents|readfile|unlink|highlight_file)\(.*\$_(GET|POST|REQUEST)' "$EXTRACT_DIR/" --type php 2>/dev/null | head -50 || true)

    echo "" >> "$REPORT_FILE"
    echo "**Total File Read/Delete indicators:** $fileop_count" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    total_findings=$((total_findings + fileop_count))

    # Summary
    echo "" >> "$REPORT_FILE"
    echo "---" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "## Summary" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "| Category | Findings |" >> "$REPORT_FILE"
    echo "|----------|----------|" >> "$REPORT_FILE"
    echo "| SQL Injection | $sqli_count |" >> "$REPORT_FILE"
    echo "| XSS | $xss_count |" >> "$REPORT_FILE"
    echo "| File Upload | $upload_count |" >> "$REPORT_FILE"
    echo "| Broken Access Control | $bac_count |" >> "$REPORT_FILE"
    echo "| PHP Object Injection | $poi_count |" >> "$REPORT_FILE"
    echo "| RCE | $rce_count |" >> "$REPORT_FILE"
    echo "| SSRF | $ssrf_count |" >> "$REPORT_FILE"
    echo "| Privilege Escalation | $privesc_count |" >> "$REPORT_FILE"
    echo "| File Read/Delete | $fileop_count |" >> "$REPORT_FILE"
    echo "| **TOTAL** | **$total_findings** |" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "> ⚠️ These are INDICATORS that need manual verification. Not all findings are true positives." >> "$REPORT_FILE"

    echo ""
    echo -e "${GREEN}[+] Scan complete!${NC}"
    echo -e "${CYAN}[*] Total potential vulnerability indicators: ${total_findings}${NC}"
    echo -e "${CYAN}[*] Report saved to: ${REPORT_FILE}${NC}"
}

# Main
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
    *)
        echo "Usage: $0 [download|scan|all]"
        echo ""
        echo "Environment variables:"
        echo "  MIN_ACTIVE   - Minimum active installs (default: 10000)"
        echo "  PAGES        - Number of API pages (default: 5)"
        echo "  PER_PAGE     - Plugins per page (default: 20)"
        echo "  WORKERS      - Download workers (default: 5)"
        echo "  OUTPUT_DIR   - Zip output dir (default: wp_zips)"
        echo "  EXTRACT_DIR  - Extract dir (default: wp_extracted)"
        echo "  REPORT_FILE  - Report output (default: vuln_report.md)"
        exit 1
        ;;
esac
