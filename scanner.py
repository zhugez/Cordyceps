#!/usr/bin/env python3
"""
Cordyceps - WordPress Plugin Vulnerability Scanner.

Context-aware static analysis based on the Patchstack Academy knowledge base.
Uses Mycelium to harvest plugins from the WordPress.org directory, then runs
regex-driven pattern matching with sanitization-aware severity adjustment.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SCANNER_NAME = "cordyceps"
SCANNER_VERSION = "1.1.0"
SCANNER_BANNER = f"{SCANNER_NAME} (Patchstack-based)"

# Directories that should never be scanned: vendored deps, build artefacts,
# VCS metadata, and the project's own test fixtures.
EXCLUDE_DIRS = {
    "vendor",
    "node_modules",
    "tests",
    "test",
    "__tests__",
    ".git",
    ".svn",
    ".hg",
    "dist",
    "build",
    "cache",
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

FAIL_ON_THRESHOLDS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "never": None,
}


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

    def to_dict(self) -> dict:
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
    """Scan WordPress plugins for Patchstack-style vulnerability patterns."""

    VULN_PATTERNS: dict[str, dict] = {
        "SQL Injection": {
            "severity": "CRITICAL",
            "patterns": [
                (r'\$wpdb\s*->\s*(query|get_var|get_row|get_col|get_results)\s*\([^)]*\$_(GET|POST|REQUEST|COOKIE)',
                 "Direct user input in $wpdb query without prepare()"),
                (r'wp_unslash\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                 "wp_unslash() removes WordPress magic quotes protection - check if used in SQL context"),
                (r'\$wpdb\s*->\s*prepare\s*\([^)]*%1s',
                 "$wpdb->prepare() with %1s placeholder bypasses parameterization"),
                (r'stripslashes\s*\(\s*\$wpdb\s*->\s*prepare',
                 "stripslashes() on prepared query result removes SQL escaping"),
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
            ],
        },
    }

    SAFE_FUNCS = (
        "esc_html", "esc_attr", "esc_url", "esc_js",
        "wp_kses", "wp_kses_post",
        "sanitize_text_field", "sanitize_email", "sanitize_file_name",
        "intval", "absint", "floatval",
        "wp_verify_nonce", "check_admin_referer", "check_ajax_referer",
        "current_user_can",
        "wpdb->prepare",
    )

    CAP_MAP = {
        "manage_options": "Admin",
        "edit_others_posts": "Editor+",
        "publish_posts": "Author+",
        "edit_posts": "Contributor+",
        "read": "Subscriber+",
    }

    SEVERITY_DOWNGRADE = {
        "CRITICAL": "HIGH",
        "HIGH": "MEDIUM",
        "MEDIUM": "LOW",
        "LOW": "LOW",
    }

    CVSS_MAP = {"CRITICAL": 9.8, "HIGH": 7.5, "MEDIUM": 5.3, "LOW": 3.1}

    def __init__(
        self,
        extract_dir: str,
        report_file: str = "vuln_report",
        quiet: bool = False,
    ) -> None:
        self.extract_dir = Path(extract_dir)
        self.report_file = report_file
        self.quiet = quiet
        self.findings: list[Finding] = []
        self.stats: dict[str, int] = defaultdict(int)

    def _log(self, msg: str) -> None:
        if not self.quiet:
            print(msg)

    @staticmethod
    def _format_context(lines: list[str], line_num: int, context: int = 3) -> str:
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        out: list[str] = []
        for i in range(start, end):
            prefix = ">>>" if i == line_num - 1 else "   "
            out.append(f"{prefix} {i + 1:4d} | {lines[i].rstrip()}")
        return "\n".join(out)

    def _nearby_sanitization(self, lines: list[str], line_num: int, window: int = 20) -> list[str]:
        start = max(0, line_num - window - 1)
        end = min(len(lines), line_num + window)
        chunk = "\n".join(lines[start:end])
        return [func for func in self.SAFE_FUNCS if func in chunk]

    def _file_auth_context(self, content: str) -> str:
        """Determine the dominant auth context for a file (computed once per file)."""
        if "wp_ajax_nopriv_" in content:
            return "Unauthenticated"
        if "wp_ajax_" in content and "wp_ajax_nopriv_" not in content:
            return "Authenticated (Subscriber+)"
        if "current_user_can" in content:
            cap_match = re.search(r"current_user_can\s*\(\s*['\"](\w+)['\"]", content)
            if cap_match:
                cap = cap_match.group(1)
                return self.CAP_MAP.get(cap, f"Capability: {cap}")
        if "permission_callback" in content and "__return_true" in content:
            return "Unauthenticated (REST)"
        if re.search(r"add_action\s*\(\s*['\"]init['\"]", content):
            return "Unauthenticated (init hook)"
        return "Unknown"

    def scan_file(self, filepath: Path, plugin_name: str) -> None:
        """Scan a single PHP file for vulnerability patterns."""
        try:
            content = filepath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.split("\n")
        auth = self._file_auth_context(content)

        try:
            rel_path = str(filepath.relative_to(self.extract_dir))
        except ValueError:
            rel_path = str(filepath)

        for vuln_type, config in self.VULN_PATTERNS.items():
            severity = config["severity"]
            for pattern, description in config["patterns"]:
                compiled = re.compile(pattern, re.IGNORECASE)
                for i, line in enumerate(lines, 1):
                    if not compiled.search(line):
                        continue

                    nearby_safe = self._nearby_sanitization(lines, i)
                    if nearby_safe:
                        adjusted_severity = self.SEVERITY_DOWNGRADE.get(severity, severity)
                        analysis = (
                            f"{description}\n\n"
                            f"Nearby sanitization found: {', '.join(nearby_safe)}\n"
                            f"Verify these are properly applied to the vulnerable parameter."
                        )
                    else:
                        adjusted_severity = severity
                        analysis = description

                    base = self.CVSS_MAP.get(adjusted_severity, 5.0)
                    if auth.startswith("Unauthenticated"):
                        cvss = base
                    elif "Admin" in auth:
                        cvss = max(base - 3.0, 2.0)
                    else:
                        cvss = max(base - 1.0, 3.0)

                    self.findings.append(Finding(
                        plugin=plugin_name,
                        file=rel_path,
                        line=i,
                        vuln_type=vuln_type,
                        severity=adjusted_severity,
                        title=f"{vuln_type} in {plugin_name}",
                        code_snippet=self._format_context(lines, i),
                        analysis=analysis,
                        auth_required=auth,
                        cvss_estimate=round(cvss, 1),
                    ))
                    self.stats[vuln_type] += 1

    def _iter_php_files(self, root: Path) -> Iterable[Path]:
        """Yield .php files under ``root``, skipping noisy directories."""
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith(".")]
            for name in filenames:
                if name.endswith(".php"):
                    yield Path(dirpath) / name

    def scan_plugin(self, plugin_dir: Path) -> None:
        plugin_name = plugin_dir.name
        for php_file in self._iter_php_files(plugin_dir):
            self.scan_file(php_file, plugin_name)

    def scan_all(self) -> None:
        if not self.extract_dir.exists():
            print(f"[ERROR] Extract directory not found: {self.extract_dir}", file=sys.stderr)
            sys.exit(1)

        plugins = [d for d in self.extract_dir.iterdir() if d.is_dir()]
        # When the extract dir IS a plugin (no plugin subdirs), scan it directly.
        if not plugins:
            self._log(f"[*] Scanning files in {self.extract_dir} directly")
            for php_file in self._iter_php_files(self.extract_dir):
                self.scan_file(php_file, self.extract_dir.name)
        else:
            self._log(f"[*] Found {len(plugins)} plugins to scan")
            for i, plugin_dir in enumerate(plugins, 1):
                self._log(f"[{i}/{len(plugins)}] Scanning {plugin_dir.name}...")
                self.scan_plugin(plugin_dir)

        self._log(f"\n[+] Scan complete! Found {len(self.findings)} potential vulnerabilities")

    def generate_markdown_report(self) -> str:
        output = f"{self.report_file}.md"
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        with open(output, "w", encoding="utf-8") as f:
            f.write("# WordPress Plugin Vulnerability Scan Report\n\n")
            f.write(f"**Date:** {now}\n")
            f.write(f"**Scanner:** {SCANNER_BANNER} v{SCANNER_VERSION}\n")
            f.write(f"**Plugins Scanned:** {len(set(finding.plugin for finding in self.findings))} plugins with findings\n")
            f.write(f"**Total Findings:** {len(self.findings)}\n\n")

            f.write("## Summary\n\n")
            f.write("| Category | Count | Severity |\n")
            f.write("|----------|-------|----------|\n")
            for vuln_type in sorted(self.stats.keys(), key=lambda x: -self.stats[x]):
                sev = self.VULN_PATTERNS.get(vuln_type, {}).get("severity", "UNKNOWN")
                f.write(f"| {vuln_type} | {self.stats[vuln_type]} | {sev} |\n")
            f.write(f"| **TOTAL** | **{len(self.findings)}** | - |\n\n")

            f.write("---\n\n")
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_findings = sorted(
                self.findings,
                key=lambda x: (severity_order.get(x.severity, 99), x.vuln_type, x.plugin),
            )

            current_severity = None
            for finding in sorted_findings:
                if finding.severity != current_severity:
                    current_severity = finding.severity
                    f.write(f"\n## {current_severity} Findings\n\n")

                f.write(f"### [{finding.severity}] {finding.vuln_type} - {finding.plugin}\n\n")
                f.write(f"**File:** `{finding.file}:{finding.line}`\n")
                f.write(f"**Auth Required:** {finding.auth_required}\n")
                f.write(f"**CVSS Estimate:** {finding.cvss_estimate}\n\n")
                f.write(f"```php\n{finding.code_snippet}\n```\n\n")
                f.write(f"**Analysis:** {finding.analysis}\n\n")
                f.write("---\n\n")

        self._log(f"[+] Markdown report saved to: {output}")
        return output

    def generate_json_report(self) -> str:
        output = f"{self.report_file}.json"
        report = {
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "scanner": SCANNER_BANNER,
            "scanner_version": SCANNER_VERSION,
            "total_findings": len(self.findings),
            "stats": dict(self.stats),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        self._log(f"[+] JSON report saved to: {output}")
        return output

    def generate_csv_report(self) -> str:
        output = f"{self.report_file}.csv"
        with open(output, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Severity", "CVSS", "Type", "Plugin", "File", "Line",
                "Auth Required", "Title", "Analysis",
            ])
            for finding in self.findings:
                writer.writerow([
                    finding.severity, finding.cvss_estimate, finding.vuln_type,
                    finding.plugin, finding.file, finding.line,
                    finding.auth_required, finding.title, finding.analysis,
                ])
        self._log(f"[+] CSV report saved to: {output}")
        return output

    def highest_severity(self) -> str | None:
        """Return the highest severity rank present in findings, or None if empty."""
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_RANK.get(f.severity, 0)).severity


def find_mycelium() -> str | None:
    """Locate the Mycelium binary across OpenClaw and Hermes install layouts."""
    home = Path.home()
    candidates: list[str] = [
        "mycelium", "mycelium.exe",
        "./mycelium", "./mycelium.exe",
        # OpenClaw layouts
        str(home / ".openclaw" / "tools" / "cordyceps" / "mycelium"),
        str(home / ".openclaw" / "tools" / "cordyceps" / "mycelium.exe"),
        str(home / ".openclaw" / "skills" / "cordyceps" / "mycelium"),
        str(home / ".openclaw" / "skills" / "cordyceps" / "mycelium.exe"),
        str(home / ".openclaw" / "skills" / "cordyceps" / "mycelium-linux-amd64"),
        str(home / ".openclaw" / "skills" / "cordyceps" / "mycelium-windows-amd64.exe"),
        # Hermes Agent layouts
        str(home / ".hermes" / "tools" / "cordyceps" / "mycelium"),
        str(home / ".hermes" / "tools" / "cordyceps" / "mycelium.exe"),
        str(home / ".hermes" / "skills" / "security" / "cordyceps" / "mycelium"),
        str(home / ".hermes" / "skills" / "security" / "cordyceps" / "mycelium.exe"),
        str(home / ".hermes" / "skills" / "security" / "cordyceps" / "mycelium-linux-amd64"),
        str(home / ".hermes" / "skills" / "security" / "cordyceps" / "mycelium-windows-amd64.exe"),
        # Legacy / tmp fallbacks
        "/tmp/openclaw-skill/mycelium",
        "/tmp/openclaw-skill/mycelium.exe",
    ]
    # Honour explicit override.
    override = os.environ.get("CORDYCEPS_MYCELIUM")
    if override:
        candidates.insert(0, override)

    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
        found = shutil.which(c)
        if found:
            return found
    return None


def download_plugins(args: argparse.Namespace) -> None:
    mycelium = find_mycelium()
    if not mycelium:
        print("[ERROR] Mycelium binary not found.", file=sys.stderr)
        print(
            "Install via:  bash install.sh   (or .\\install.ps1 on Windows)\n"
            "Or fetch latest manually from https://github.com/zhugez/Mycelium/releases/latest",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[*] Using Mycelium at: {mycelium}")
    cmd = [
        mycelium,
        "--min-active", str(args.min_active),
        "--pages", str(args.pages),
        "--per-page", str(args.per_page),
        "--workers", str(args.workers),
        "--output-dir", args.output_dir,
        "--extract-dir", args.extract_dir,
        "--csv-path", args.csv_path,
    ]
    if not args.list_only:
        cmd.append("--extract")
    else:
        cmd.append("--list-only")

    print(f"[*] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        print(f"[ERROR] Mycelium exited with code {result.returncode}", file=sys.stderr)
        sys.exit(1)


def _exit_code_for_findings(scanner: PatchstackScanner, fail_on: str) -> int:
    threshold = FAIL_ON_THRESHOLDS.get(fail_on)
    if threshold is None:
        return 0
    threshold_rank = SEVERITY_RANK[threshold]
    for finding in scanner.findings:
        if SEVERITY_RANK.get(finding.severity, 0) >= threshold_rank:
            return 1
    return 0


def _add_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-d", "--extract-dir", default="wp_extracted",
                        help="Directory with extracted plugins")
    parser.add_argument("-r", "--report", default="vuln_report",
                        help="Report output filename (without extension)")
    parser.add_argument("-f", "--format", nargs="+",
                        choices=["md", "json", "csv"], default=["md", "json"],
                        help="Report formats (default: md json)")
    parser.add_argument("--fail-on", choices=list(FAIL_ON_THRESHOLDS.keys()),
                        default="never",
                        help="Exit non-zero when findings at this severity (or higher) exist")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress informational output (CI-friendly)")


def _add_download_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-m", "--min-active", type=int, default=10000,
                        help="Minimum active installs (default: 10000)")
    parser.add_argument("-p", "--pages", type=int, default=5,
                        help="API pages to fetch (default: 5)")
    parser.add_argument("--per-page", type=int, default=20,
                        help="Plugins per page (default: 20)")
    parser.add_argument("-w", "--workers", type=int, default=5,
                        help="Download workers (default: 5)")
    parser.add_argument("-o", "--output-dir", default="wp_zips",
                        help="ZIP output directory")
    parser.add_argument("-e", "--extract-dir", default="wp_extracted",
                        help="Extraction directory")
    parser.add_argument("-c", "--csv-path", default="plugins.csv",
                        help="CSV report path")
    parser.add_argument("--list-only", action="store_true",
                        help="Only list plugins, don't download")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog=SCANNER_NAME,
        description=f"{SCANNER_BANNER} - WordPress plugin vulnerability scanner",
    )
    parser.add_argument("--version", action="version",
                        version=f"{SCANNER_NAME} {SCANNER_VERSION}")
    subparsers = parser.add_subparsers(dest="command")

    dl_parser = subparsers.add_parser("download", help="Download plugins with Mycelium")
    _add_download_args(dl_parser)

    scan_parser = subparsers.add_parser("scan", help="Scan extracted plugins")
    _add_scan_args(scan_parser)

    all_parser = subparsers.add_parser("all", help="Download and scan (full pipeline)")
    _add_download_args(all_parser)
    all_parser.add_argument("-r", "--report", default="vuln_report",
                            help="Report output filename (without extension)")
    all_parser.add_argument("-f", "--format", nargs="+",
                            choices=["md", "json", "csv"], default=["md", "json"])
    all_parser.add_argument("--fail-on", choices=list(FAIL_ON_THRESHOLDS.keys()),
                            default="never",
                            help="Exit non-zero when findings at this severity (or higher) exist")
    all_parser.add_argument("--quiet", action="store_true",
                            help="Suppress informational output (CI-friendly)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command in ("download", "all"):
        download_plugins(args)

    if args.command in ("scan", "all"):
        scanner = PatchstackScanner(
            args.extract_dir,
            args.report,
            quiet=getattr(args, "quiet", False),
        )
        scanner.scan_all()

        if "md" in args.format:
            scanner.generate_markdown_report()
        if "json" in args.format:
            scanner.generate_json_report()
        if "csv" in args.format:
            scanner.generate_csv_report()

        if not getattr(args, "quiet", False):
            print("\n" + "=" * 60)
            print("SCAN SUMMARY")
            print("=" * 60)
            for vuln_type in sorted(scanner.stats.keys(), key=lambda x: -scanner.stats[x]):
                print(f"  {vuln_type}: {scanner.stats[vuln_type]}")
            print(f"\n  TOTAL: {len(scanner.findings)} potential vulnerabilities")
            print("=" * 60)

        return _exit_code_for_findings(scanner, args.fail_on)

    return 0


if __name__ == "__main__":
    sys.exit(main())
