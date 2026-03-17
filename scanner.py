#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner - Context-Aware Analysis
Based on Patchstack Academy vulnerability knowledge base.
Uses Mycelium to download plugins, then performs deep static analysis.
"""

import os
import re
import sys
import csv
import json
import subprocess
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
from datetime import datetime


@dataclass
class Finding:
    plugin: str
    file: str
    line: int
    vuln_type: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    code_snippet: str
    analysis: str
    auth_required: str = "Unknown"
    cvss_estimate: float = 0.0

    def to_dict(self):
        return {
            "plugin": self.plugin,
            "file": self.file,
            "line": self.line,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "code_snippet": self.code_snippet,
            "analysis": self.analysis,
            "auth_required": self.auth_required,
            "cvss_estimate": self.cvss_estimate,
        }


class PatchstackScanner:
    """Scan WordPress plugins based on Patchstack vulnerability patterns."""

    # Patterns organized by vulnerability type
    VULN_PATTERNS = {
        "SQL Injection": {
            "severity": "CRITICAL",
            "patterns": [
                # Direct SQL query with user input
                (r'\$wpdb\s*->\s*(query|get_var|get_row|get_col|get_results)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                 "Direct user input in $wpdb query without prepare()"),
                # wp_unslash before SQL
                (r'wp_unslash\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                 "wp_unslash() removes WordPress magic quotes protection - check if used in SQL context"),
                # %1s placeholder bypass
                (r'\$wpdb\s*->\s*prepare\s*\([^)]*%1s',
                 "$wpdb->prepare() with %1s placeholder bypasses parameterization"),
                # stripslashes on prepared query
                (r'stripslashes\s*\(\s*\$wpdb\s*->\s*prepare',
                 "stripslashes() on prepared query result removes SQL escaping"),
                # Concatenation in query
                (r'\$wpdb\s*->\s*(query|get_var|get_row|get_col|get_results)\s*\(\s*["\'].*\.\s*\$(?!wpdb)',
                 "String concatenation in SQL query - possible injection point"),
            ],
        },
        "Cross-Site Scripting (XSS)": {
            "severity": "HIGH",
            "patterns": [
                (r'echo\s+.*\$_(GET|POST|REQUEST|SERVER)',
                 "Direct echo of user input without escaping"),
                (r'echo\s+.*\$_SERVER\s*\[\s*[\'"]PHP_SELF',
                 "$_SERVER['PHP_SELF'] reflected without escaping - XSS via URL"),
                (r'(add_query_arg|remove_query_arg)\s*\(',
                 "add_query_arg()/remove_query_arg() output needs esc_url()"),
                (r'printf?\s*\(\s*[\'"]<[^>]*%s[^>]*>[\'"]',
                 "printf/sprintf with %s inside HTML tags without escaping"),
            ],
        },
        "Shortcode XSS": {
            "severity": "HIGH",
            "patterns": [
                (r'add_shortcode\s*\(\s*[\'"][^\'"]+[\'"]\s*,',
                 "Shortcode registration - verify attributes are escaped in output"),
            ],
        },
        "Arbitrary File Upload": {
            "severity": "CRITICAL",
            "patterns": [
                (r'move_uploaded_file\s*\(',
                 "File upload via move_uploaded_file() - check extension validation"),
                (r'test_type[\'"\s]*=>\s*false',
                 "WordPress upload type check disabled (test_type => false)"),
                (r'ZipArchive\s*::\s*extractTo|unzip_file\s*\(',
                 "ZIP extraction - check for path traversal and contained file types"),
                (r'\$_FILES\s*\[',
                 "Direct $_FILES access - verify file type validation"),
                (r'WP_Filesystem_Direct\s*::\s*(put_contents|move|copy)',
                 "WP_Filesystem file write - check if path is user-controlled"),
            ],
        },
        "Broken Access Control": {
            "severity": "HIGH",
            "patterns": [
                (r'permission_callback[\'"\s]*=>\s*[\'"]?__return_true',
                 "REST route with __return_true permission - accessible to anyone"),
                (r'wp_ajax_nopriv_',
                 "Unauthenticated AJAX handler - verify it should be public"),
                (r'wp_localize_script\s*\([^)]*nonce[^)]*wp_create_nonce',
                 "Nonce exposed to frontend via wp_localize_script - check if combined with capability check"),
            ],
        },
        "PHP Object Injection": {
            "severity": "CRITICAL",
            "patterns": [
                (r'(?<!maybe_)unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                 "unserialize() with direct user input - PHP Object Injection"),
                (r'maybe_unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                 "maybe_unserialize() with user input - Object Injection risk"),
                (r'unserialize\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)',
                 "Base64-decoded user input passed to unserialize()"),
            ],
        },
        "Remote Code Execution (RCE)": {
            "severity": "CRITICAL",
            "patterns": [
                (r'(system|exec|shell_exec|passthru|proc_open)\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "OS command execution with user input"),
                (r'eval\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "eval() with user input - arbitrary PHP code execution"),
                (r'call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)',
                 "Dynamic function call with user-controlled callback"),
                (r'assert\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "assert() with user input - code execution in PHP < 8"),
                (r'create_function\s*\(',
                 "create_function() is deprecated and equivalent to eval()"),
                (r'preg_replace\s*\(\s*[\'"]/.*/e[\'"]',
                 "preg_replace with /e modifier - code execution"),
            ],
        },
        "Local File Inclusion (LFI)": {
            "severity": "CRITICAL",
            "patterns": [
                (r'(include|require)(_once)?\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "File inclusion with user-controlled path"),
                (r'(include|require)(_once)?\s+\$(?!this)',
                 "Dynamic file inclusion with variable path - check source"),
            ],
        },
        "Server-Side Request Forgery (SSRF)": {
            "severity": "HIGH",
            "patterns": [
                (r'wp_remote_(get|post|head|request)\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "WordPress HTTP request with user-controlled URL"),
                (r'file_get_contents\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "file_get_contents() with user-controlled URL"),
                (r'curl_exec\s*\(',
                 "cURL execution - verify URL is not user-controlled"),
            ],
        },
        "Privilege Escalation": {
            "severity": "CRITICAL",
            "patterns": [
                (r'update_option\s*\(\s*\$_(GET|POST|REQUEST)',
                 "update_option() with user-controlled key - can set default_role to administrator"),
                (r'update_user_meta\s*\(\s*[^,]+,\s*\$_(GET|POST|REQUEST)',
                 "update_user_meta() with user-controlled meta_key - can escalate via wp_capabilities"),
                (r'wp_set_auth_cookie\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "Setting auth cookie with user-controlled user ID"),
                (r'wp_set_current_user\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "Setting current user with user-controlled ID"),
                (r'wp_insert_user\s*\(\s*.*[\'"]role[\'"].*\$_(GET|POST|REQUEST)',
                 "User creation with user-controlled role parameter"),
                (r'->set_role\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "Role assignment with user-controlled value"),
            ],
        },
        "Arbitrary File Read": {
            "severity": "HIGH",
            "patterns": [
                (r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)',
                 "Reading file with user-controlled path"),
                (r'readfile\s*\(\s*\$_(GET|POST|REQUEST)',
                 "readfile() with user-controlled path"),
                (r'(highlight_file|show_source)\s*\(\s*\$_(GET|POST|REQUEST)',
                 "Source file disclosure with user-controlled path"),
            ],
        },
        "Arbitrary File Deletion": {
            "severity": "HIGH",
            "patterns": [
                (r'unlink\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "File deletion with user-controlled path"),
                (r'wp_delete_file\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "WordPress file deletion with user-controlled path"),
            ],
        },
        "Open Redirect": {
            "severity": "MEDIUM",
            "patterns": [
                (r'wp_redirect\s*\(\s*\$_(GET|POST|REQUEST)',
                 "Redirect with user-controlled URL - use wp_safe_redirect()"),
                (r'header\s*\(\s*[\'"]Location:\s*.*\$_(GET|POST|REQUEST)',
                 "Header redirect with user-controlled URL"),
            ],
        },
        "CSRF": {
            "severity": "MEDIUM",
            "patterns": [
                (r'add_action\s*\(\s*[\'"]admin_init[\'"].*update_option',
                 "admin_init with update_option - check for nonce verification"),
                (r'add_action\s*\(\s*[\'"]init[\'"].*(?:update_option|wp_delete|wp_insert|wp_update)',
                 "init hook with state change - verify nonce and capability checks"),
            ],
        },
        "Type Juggling": {
            "severity": "MEDIUM",
            "patterns": [
                (r'==\s*\$_(GET|POST|REQUEST)',
                 "Loose comparison with user input - use === instead"),
                (r'hash_equals\s*\(|===',
                 None),  # Safe pattern marker
            ],
        },
    }

    def __init__(self, extract_dir: str, report_file: str = "vuln_report"):
        self.extract_dir = Path(extract_dir)
        self.report_file = report_file
        self.findings: list[Finding] = []
        self.stats: dict[str, int] = defaultdict(int)

    def get_context(self, filepath: Path, line_num: int, context: int = 3) -> str:
        """Get code context around a line."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            start = max(0, line_num - context - 1)
            end = min(len(lines), line_num + context)

            result = []
            for i in range(start, end):
                prefix = ">>>" if i == line_num - 1 else "   "
                result.append(f"{prefix} {i + 1:4d} | {lines[i].rstrip()}")
            return "\n".join(result)
        except Exception:
            return "(could not read context)"

    def check_nearby_sanitization(self, filepath: Path, line_num: int, window: int = 20) -> list[str]:
        """Check for sanitization/escaping functions near the vulnerable line."""
        safe_funcs = [
            "esc_html", "esc_attr", "esc_url", "esc_js",
            "wp_kses", "wp_kses_post",
            "sanitize_text_field", "sanitize_email", "sanitize_file_name",
            "intval", "absint", "floatval",
            "wp_verify_nonce", "check_admin_referer", "check_ajax_referer",
            "current_user_can",
            "wpdb->prepare",
        ]

        found = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            start = max(0, line_num - window - 1)
            end = min(len(lines), line_num + window)
            chunk = "".join(lines[start:end])

            for func in safe_funcs:
                if func in chunk:
                    found.append(func)
        except Exception:
            pass

        return found

    def determine_auth_context(self, filepath: Path, line_num: int) -> str:
        """Determine what authentication context the code runs in."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Check for hook context
            if "wp_ajax_nopriv_" in content:
                return "Unauthenticated"
            if "wp_ajax_" in content and "wp_ajax_nopriv_" not in content:
                return "Authenticated (Subscriber+)"
            if "current_user_can" in content:
                # Try to extract the capability
                cap_match = re.search(r"current_user_can\s*\(\s*['\"](\w+)['\"]", content)
                if cap_match:
                    cap = cap_match.group(1)
                    cap_map = {
                        "manage_options": "Admin",
                        "edit_others_posts": "Editor+",
                        "publish_posts": "Author+",
                        "edit_posts": "Contributor+",
                        "read": "Subscriber+",
                    }
                    return cap_map.get(cap, f"Capability: {cap}")
            if "permission_callback" in content and "__return_true" in content:
                return "Unauthenticated (REST)"
            if re.search(r"add_action\s*\(\s*['\"]init['\"]", content):
                return "Unauthenticated (init hook)"

        except Exception:
            pass
        return "Unknown"

    def scan_file(self, filepath: Path, plugin_name: str):
        """Scan a single PHP file for vulnerability patterns."""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")
        except Exception:
            return

        for vuln_type, config in self.VULN_PATTERNS.items():
            severity = config["severity"]
            for pattern, description in config["patterns"]:
                if description is None:
                    continue  # Skip safe pattern markers

                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # Check for nearby sanitization
                        nearby_safe = self.check_nearby_sanitization(filepath, i)

                        # Reduce severity if sanitization is present
                        adjusted_severity = severity
                        if nearby_safe:
                            # If proper sanitization is found nearby, mark as potential false positive
                            analysis = (
                                f"{description}\n\n"
                                f"⚠️ Nearby sanitization found: {', '.join(nearby_safe)}\n"
                                f"Verify these are properly applied to the vulnerable parameter."
                            )
                            # Lower severity by one level
                            sev_map = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
                            adjusted_severity = sev_map.get(severity, severity)
                        else:
                            analysis = description

                        auth = self.determine_auth_context(filepath, i)

                        # CVSS estimate
                        cvss_map = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1}
                        if auth == "Unauthenticated" or auth.startswith("Unauthenticated"):
                            cvss = cvss_map.get(adjusted_severity, 5.0)
                        elif "Admin" in auth:
                            cvss = max(cvss_map.get(adjusted_severity, 5.0) - 3.0, 2.0)
                        else:
                            cvss = max(cvss_map.get(adjusted_severity, 5.0) - 1.0, 3.0)

                        rel_path = str(filepath.relative_to(self.extract_dir))

                        finding = Finding(
                            plugin=plugin_name,
                            file=rel_path,
                            line=i,
                            vuln_type=vuln_type,
                            severity=adjusted_severity,
                            title=f"{vuln_type} in {plugin_name}",
                            code_snippet=self.get_context(filepath, i),
                            analysis=analysis,
                            auth_required=auth,
                            cvss_estimate=round(cvss, 1),
                        )
                        self.findings.append(finding)
                        self.stats[vuln_type] += 1

    def scan_plugin(self, plugin_dir: Path):
        """Scan all PHP files in a plugin directory."""
        plugin_name = plugin_dir.name
        php_files = list(plugin_dir.rglob("*.php"))

        for php_file in php_files:
            self.scan_file(php_file, plugin_name)

    def scan_all(self):
        """Scan all plugins in the extract directory."""
        if not self.extract_dir.exists():
            print(f"[ERROR] Extract directory not found: {self.extract_dir}")
            sys.exit(1)

        plugins = [d for d in self.extract_dir.iterdir() if d.is_dir()]
        print(f"[*] Found {len(plugins)} plugins to scan")

        for i, plugin_dir in enumerate(plugins, 1):
            print(f"[{i}/{len(plugins)}] Scanning {plugin_dir.name}...")
            self.scan_plugin(plugin_dir)

        print(f"\n[+] Scan complete! Found {len(self.findings)} potential vulnerabilities")

    def generate_markdown_report(self):
        """Generate a detailed Markdown report."""
        output = f"{self.report_file}.md"

        with open(output, "w", encoding="utf-8") as f:
            f.write("# WordPress Plugin Vulnerability Scan Report\n\n")
            f.write(f"**Date:** {datetime.now(tz=__import__('datetime').timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write(f"**Scanner:** wp-vuln-scanner (Patchstack-based)\n")
            f.write(f"**Plugins Scanned:** {len(set(finding.plugin for finding in self.findings))} plugins with findings\n")
            f.write(f"**Total Findings:** {len(self.findings)}\n\n")

            # Summary table
            f.write("## Summary\n\n")
            f.write("| Category | Count | Severity |\n")
            f.write("|----------|-------|----------|\n")
            for vuln_type in sorted(self.stats.keys(), key=lambda x: -self.stats[x]):
                sev = self.VULN_PATTERNS.get(vuln_type, {}).get("severity", "UNKNOWN")
                f.write(f"| {vuln_type} | {self.stats[vuln_type]} | {sev} |\n")
            f.write(f"| **TOTAL** | **{len(self.findings)}** | - |\n\n")

            # Critical findings first
            f.write("---\n\n")
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_findings = sorted(
                self.findings,
                key=lambda x: (severity_order.get(x.severity, 99), x.vuln_type, x.plugin)
            )

            current_severity = None
            for finding in sorted_findings:
                if finding.severity != current_severity:
                    current_severity = finding.severity
                    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(current_severity, "⚪")
                    f.write(f"\n## {emoji} {current_severity} Findings\n\n")

                f.write(f"### [{finding.severity}] {finding.vuln_type} — {finding.plugin}\n\n")
                f.write(f"**File:** `{finding.file}:{finding.line}`\n")
                f.write(f"**Auth Required:** {finding.auth_required}\n")
                f.write(f"**CVSS Estimate:** {finding.cvss_estimate}\n\n")
                f.write(f"```php\n{finding.code_snippet}\n```\n\n")
                f.write(f"**Analysis:** {finding.analysis}\n\n")
                f.write("---\n\n")

        print(f"[+] Markdown report saved to: {output}")

    def generate_json_report(self):
        """Generate JSON report for programmatic processing."""
        output = f"{self.report_file}.json"

        report = {
            "scan_date": datetime.now(tz=__import__('datetime').timezone.utc).isoformat(),
            "scanner": "wp-vuln-scanner (Patchstack-based)",
            "total_findings": len(self.findings),
            "stats": dict(self.stats),
            "findings": [f.to_dict() for f in self.findings],
        }

        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"[+] JSON report saved to: {output}")

    def generate_csv_report(self):
        """Generate CSV report."""
        output = f"{self.report_file}.csv"

        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Severity", "CVSS", "Type", "Plugin", "File", "Line",
                "Auth Required", "Title", "Analysis"
            ])
            for finding in self.findings:
                writer.writerow([
                    finding.severity, finding.cvss_estimate, finding.vuln_type,
                    finding.plugin, finding.file, finding.line,
                    finding.auth_required, finding.title, finding.analysis
                ])

        print(f"[+] CSV report saved to: {output}")


def find_mycelium() -> Optional[str]:
    """Find the Mycelium binary."""
    candidates = [
        "mycelium", "mycelium.exe",
        "./mycelium", "./mycelium.exe",
        os.path.expanduser("~/.openclaw/tools/wp-vuln-scanner/mycelium"),
        os.path.expanduser("~/.openclaw/tools/wp-vuln-scanner/mycelium.exe"),
        "/tmp/openclaw-skill/mycelium",
        "/tmp/openclaw-skill/mycelium.exe",
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
        # Check PATH
        import shutil
        found = shutil.which(c)
        if found:
            return found
    return None


def download_plugins(args):
    """Use Mycelium to download plugins."""
    mycelium = find_mycelium()
    if not mycelium:
        print("[ERROR] Mycelium binary not found!")
        print("Download from: https://github.com/zhugez/Mycelium/releases/download/v1.0.0/")
        sys.exit(1)

    print(f"[*] Using Mycelium at: {mycelium}")
    cmd = [
        mycelium,
        "--min-active", str(args.min_active),
        "--pages", str(args.pages),
        "--per-page", str(args.per_page),
        "--workers", str(args.workers),
        "--output-dir", args.output_dir,
        "--extract",
        "--extract-dir", args.extract_dir,
        "--csv-path", args.csv_path,
    ]

    if args.list_only:
        cmd.append("--list-only")
        cmd = [c for c in cmd if c not in ("--extract",)]

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print(f"[ERROR] Mycelium exited with code {result.returncode}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="WordPress Vulnerability Scanner (Patchstack-based)"
    )
    subparsers = parser.add_subparsers(dest="command")

    # Download command
    dl_parser = subparsers.add_parser("download", help="Download plugins with Mycelium")
    dl_parser.add_argument("-m", "--min-active", type=int, default=10000,
                          help="Minimum active installs (default: 10000)")
    dl_parser.add_argument("-p", "--pages", type=int, default=5,
                          help="API pages to fetch (default: 5)")
    dl_parser.add_argument("--per-page", type=int, default=20,
                          help="Plugins per page (default: 20)")
    dl_parser.add_argument("-w", "--workers", type=int, default=5,
                          help="Download workers (default: 5)")
    dl_parser.add_argument("-o", "--output-dir", default="wp_zips",
                          help="ZIP output directory")
    dl_parser.add_argument("-e", "--extract-dir", default="wp_extracted",
                          help="Extraction directory")
    dl_parser.add_argument("-c", "--csv-path", default="plugins.csv",
                          help="CSV report path")
    dl_parser.add_argument("--list-only", action="store_true",
                          help="Only list plugins, don't download")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan extracted plugins")
    scan_parser.add_argument("-d", "--extract-dir", default="wp_extracted",
                            help="Directory with extracted plugins")
    scan_parser.add_argument("-r", "--report", default="vuln_report",
                            help="Report output filename (without extension)")
    scan_parser.add_argument("-f", "--format", nargs="+",
                            choices=["md", "json", "csv"], default=["md", "json"],
                            help="Report formats (default: md json)")

    # All command
    all_parser = subparsers.add_parser("all", help="Download and scan (full pipeline)")
    all_parser.add_argument("-m", "--min-active", type=int, default=10000)
    all_parser.add_argument("-p", "--pages", type=int, default=5)
    all_parser.add_argument("--per-page", type=int, default=20)
    all_parser.add_argument("-w", "--workers", type=int, default=5)
    all_parser.add_argument("-o", "--output-dir", default="wp_zips")
    all_parser.add_argument("-e", "--extract-dir", default="wp_extracted")
    all_parser.add_argument("-c", "--csv-path", default="plugins.csv")
    all_parser.add_argument("-r", "--report", default="vuln_report")
    all_parser.add_argument("-f", "--format", nargs="+",
                            choices=["md", "json", "csv"], default=["md", "json"])

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command in ("download", "all"):
        download_plugins(args)

    if args.command in ("scan", "all"):
        scanner = PatchstackScanner(args.extract_dir, args.report)
        scanner.scan_all()

        if "md" in args.format:
            scanner.generate_markdown_report()
        if "json" in args.format:
            scanner.generate_json_report()
        if "csv" in args.format:
            scanner.generate_csv_report()

        # Print summary
        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)
        for vuln_type in sorted(scanner.stats.keys(), key=lambda x: -scanner.stats[x]):
            print(f"  {vuln_type}: {scanner.stats[vuln_type]}")
        print(f"\n  TOTAL: {len(scanner.findings)} potential vulnerabilities")
        print("=" * 60)


if __name__ == "__main__":
    main()
