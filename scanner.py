#!/usr/bin/env python3
"""
Cordyceps - WordPress Plugin Vulnerability Scanner.

Context-aware static analysis based on the Patchstack Academy knowledge base.
Uses Mycelium to harvest plugins from the WordPress.org directory, then runs
regex-driven pattern matching with sanitization-aware severity adjustment.
"""

from __future__ import annotations

import argparse
import bisect
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
    # php-scoper output. Third-party code with a plugin-local namespace, and the only
    # place a `create_function()` survived to the top of the report.
    "vendor_prefixed",
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

FUNC_DECL = re.compile(r"\bfunction\s+&?\s*(\w+)\s*\(")

# Anonymous closures are function bodies too, and the name is optional here on purpose.
# `add_action('wp_ajax_x', function() { ... })` is the modern registration idiom; a nameless
# body resolved to no span at all, so scope fell back to the whole file -- the sink gate passed
# on any `$wpdb` anywhere in the file, the one-lead-per-function dedup never fired, and a
# `current_user_can()` two lines above the match was invisible. The empty name is harmless:
# every lookup keyed by name (callback exposure, the guard index, BAC handlers) searches for a
# `\w+` that can never be "".
ANON_OK = re.compile(r"\bfunction\s*&?\s*(\w*)\s*\(")

VAR_NAME = re.compile(r"\$(\w+)")
# `$x =`, `$x['k'] =`, `$x .=` -- never `==`, `!=`, `>=`, `<=` or the `=>` of an array literal.
ASSIGN = re.compile(r"\$(\w+)\s*(?:\[[^\]]*\])?\s*\.?=(?![=>])")
# End of a statement or of a block: where the backward scan for the statement start stops.
STMT_BREAK = re.compile(r"[;{}]")

# Line whose first non-space token opens or continues a comment. `#[` is a PHP 8 attribute.
COMMENT_LINE = re.compile(r"\s*(//|#(?!\[)|\*|/\*)")

# `isset($_GET['x'])` tests a key; it never uses the value. Patterns are matched against the
# line with these calls blanked out, so a guard is not mistaken for a sink -- 63 of the 121
# `echo ... $_GET` findings over 100 plugins had the superglobal nowhere else on the line.
# Applied twice: one nesting level, e.g. `empty(helper('k', $_GET, ''))`.
GUARD_CALL = re.compile(r"\b(?:isset|empty|array_key_exists)\s*\([^()]*\)")


def _probe(line: str) -> str:
    """The line as the patterns see it: key-existence checks removed, length preserved."""
    for _ in range(2):
        line = GUARD_CALL.sub(lambda mm: " " * len(mm.group(0)), line)
    return line


SUPERGLOBAL = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[")

# `add_query_arg()` reads the current `$_SERVER['REQUEST_URI']` without naming a superglobal,
# so the escape check had nothing to look at and every `echo esc_url(add_query_arg(...))` was
# reported: 28 of 28 such findings on the fresh corpus were already escaped that way. Treat the
# call itself as the tainted spot and the existing proof-of-escape rule does the rest.
XSS_SPOT = re.compile(SUPERGLOBAL.pattern + r"|\b(?:add|remove)_query_arg\s*\(")

# Wrappers that prove the value they enclose is not the bug the rule describes. `intval`
# makes a value harmless everywhere; `esc_attr` only makes it harmless as output, so the
# two sets are applied to different categories.
NUMERIC_SAFE = frozenset({"intval", "absint", "floatval", "count", "sizeof"})
OUTPUT_SAFE = frozenset({
    "esc_attr", "esc_html", "esc_url", "esc_js", "esc_textarea",
    "esc_attr_e", "esc_html_e", "wp_kses", "wp_kses_post",
})
# A nonce check is the defence, not the bug. The first false positive ever reported against
# this scanner was `wp_verify_nonce(sanitize_text_field(wp_unslash($_POST[...])))` labelled
# CRITICAL SQL Injection -- it pointed at the plugin's own protection. A value handed to
# these is compared against a hash, never used as data, so it is safe for every category.
NONCE_SAFE = frozenset({
    "wp_verify_nonce", "wp_create_nonce", "check_admin_referer", "check_ajax_referer",
})


def _all_escaped(line: str, safe: frozenset[str], spots_re: re.Pattern = SUPERGLOBAL) -> bool:
    """True when EVERY superglobal on the line sits inside a closed call to a `safe` function.

    `echo esc_attr($_GET['x'])` is the fix the XSS rule recommends, not the bug it looks
    for; 42 of 181 XSS findings over 100 plugins were already escaped that way. One bare
    occurrence keeps the finding -- this suppresses on proof, never on a majority. A call
    whose parenthesis does not close on this line proves nothing and is ignored.
    """
    spots = [m.start() for m in spots_re.finditer(line)]
    if not spots:
        return False
    covered: set[int] = set()
    for m in re.finditer(r"\b(\w+)\s*\(", line):
        if m.group(1) not in safe:
            continue
        depth, i = 0, m.end() - 1
        while i < len(line):
            if line[i] == "(":
                depth += 1
            elif line[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        else:
            continue
        covered.update(s for s in spots if m.end() <= s < i)
    return len(covered) == len(spots)

# add_action('wp_ajax_nopriv_x', 'cb') / (..., array($this, 'cb')) / (..., [$this, 'cb'])
CALLBACK_REG = re.compile(
    r"""['"](wp_ajax_nopriv_|wp_ajax_)[^'"]*['"]\s*,\s*"""
    # Three registration forms: a bare function name, `array($obj, 'method')`, and the
    # WordPress Plugin Boilerplate loader's `add_action($hook, $obj, 'method')`. The third
    # was 27 of the 71 nopriv findings whose handler name could not be read at all.
    r"""(?:(?:array\s*\(|\[)\s*[^,]+,\s*|\$[\w>\-\[\]'"]+\s*,\s*)?['"](\w+)['"]""")

# register_rest_route() spreads one route over several lines, so the handler is never on the
# `permission_callback` line that matched. 45 of 51 name it within 8 lines of that key.
REST_CB = re.compile(
    r"""['"]callback['"]\s*=>\s*(?:(?:array\s*\(|\[)\s*[^,]+,\s*)?['"](\w+)['"]""")

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
                # Deleted: `$wpdb->query("..." . $var)`. Hand-checked twice over 100 plugins,
                # 37/37 then 15/15 false -- always a table or column name ($table, $wpdb->prefix,
                # $column->Field), never a request value, and it was 47% of the CRITICAL queue.
                # ponytail: this drops laundered-request-var SQLi, which is real and common. A
                # line-scoped regex cannot tell it from a table name; taint tracking is the fix.
            ],
        },
        "Cross-Site Scripting (XSS)": {
            "severity": "HIGH",
            "patterns": [
                (r'echo\s+.*\$_(GET|POST|REQUEST|SERVER)',
                 "Direct echo of user input without escaping"),
                (r'echo\s+.*\$_SERVER\s*\[\s*[\'"]PHP_SELF',
                 "$_SERVER['PHP_SELF'] reflected without escaping - XSS via URL"),
                # Echo required on the line. Bare `add_query_arg(` is a call to a standard
                # WP URL helper, present in most plugins: 870 hits over 100 plugins, 64% with
                # no request source in the enclosing function. The bug shape is the *output*.
                (r'\b(echo|print|<\?=)\b.*(add_query_arg|remove_query_arg)\s*\(',
                 "add_query_arg()/remove_query_arg() output needs esc_url()"),
                # Request value required in the arguments. The bare form matched the HTML
                # template alone -- every `printf('<a href="%s">', esc_url($x))` in WordPress:
                # 77 hits over 100 plugins, 6 of them with any superglobal on the line.
                (r'printf?\s*\(\s*[\'"]<[^>]*%s[^>]*>[\'"].*\$_(GET|POST|REQUEST|SERVER)',
                 "printf/sprintf renders a request value inside an HTML tag unescaped"),
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
                # Not inside a conditional: `if ( ! isset( $_FILES['x'] ) )` is the guard, not
                # the bug, and 40% of this rule's 145 hits over 100 plugins were exactly that.
                (r'^(?!\s*(?:if|elseif|while)\b).*\$_FILES\s*\[',
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
                # Deleted: `wp_localize_script(... 'nonce' => wp_create_nonce(...))`. That is the
                # documented way to hand a nonce to JS -- the defence every AJAX plugin is supposed
                # to ship, not a bug. 52 raw hits over 18 of 100 plugins, and its own text said
                # "check if combined with capability check", which is a hedge, not a finding.
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
                # Deleted: `(include|require)(_once)?\s+\$(?!this)`. Its own description was
                # "check source" and nothing ever did: 324 hits over 100 plugins, 92% with no
                # request source in the enclosing function, every PSR autoloader among them.
                # All 3 CVSS-9.8 findings in that run were false and 2 came from this rule.
            ],
        },
        "Server-Side Request Forgery (SSRF)": {
            "severity": "HIGH",
            "patterns": [
                (r'wp_remote_(get|post|head|request)\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "WordPress HTTP request with user-controlled URL"),
                (r'file_get_contents\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "file_get_contents() with user-controlled URL"),
                # Deleted: `curl_exec\s*\(`. Its description was "verify URL is not
                # user-controlled" and nothing verified: 43 hits over 100 plugins, 86% with no
                # request source in the enclosing function. Matching cURL is not a finding.
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
                # The three rules above demand the superglobal syntactically inside the sink
                # call. Real code launders it first, so across 26 plugins that a cross-function
                # hunt flagged for file read they matched 0 lines against 557 sink lines.
                # This is SQL Injection's shape: match the source, let SINKS prove the sink is
                # in the same function. 13 findings on those 26 plugins.
                (r'wp_unslash\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                 "Request value unslashed in a function that reads a file by path"),
            ],
        },
        "Arbitrary File Deletion": {
            "severity": "HIGH",
            "patterns": [
                (r'unlink\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "File deletion with user-controlled path"),
                (r'wp_delete_file\s*\(\s*.*\$_(GET|POST|REQUEST)',
                 "WordPress file deletion with user-controlled path"),
                # Same recall hole as Arbitrary File Read: 0 raw matches against 305 sink lines
                # over the 23 plugins the file-deletion hunt flagged. 28 findings with the
                # source-plus-sink shape.
                (r'wp_unslash\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                 "Request value unslashed in a function that deletes a file"),
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
        "Type Juggling": {
            "severity": "MEDIUM",
            "patterns": [
                # `(?<![=!<>])==(?!=)`: the bare `==` matched the tail of `===`, so the rule
                # fired on the strict comparison it exists to recommend. All 157 hits over 100
                # plugins were `'x' === $_GET['action']` or `!==`. Loose `==` only.
                (r'(?<![=!<>])==(?!=)\s*\$_(GET|POST|REQUEST)',
                 "Loose comparison with user input - use === instead"),
            ],
        },
    }

    # Curated literal list, deliberately NOT a `esc_|sanitize_` prefix rule: esc_sql(),
    # esc_url_raw(), sanitize_sql_orderby() and $wpdb->esc_like() all match such a prefix
    # and none of them make a value safe. Measured: the prefix version wrongly downgrades
    # 10 real findings (9 CRITICAL SQLi, 1 HIGH XSS) on the corpus.
    SAFE_FUNCS = (
        "esc_html", "esc_attr", "esc_url", "esc_js", "esc_textarea",
        "wp_kses", "wp_kses_post",
        "sanitize_text_field", "sanitize_email", "sanitize_file_name",
        "sanitize_key", "sanitize_title", "sanitize_title_with_dashes",
        "sanitize_textarea_field", "sanitize_html_class", "sanitize_hex_color",
        "sanitize_url", "sanitize_user",
        "wc_clean", "wc_sanitize_taxonomy_name",
        "wp_check_filetype", "wp_check_filetype_and_ext", "wp_handle_upload",
        "wp_handle_sideload", "media_handle_upload", "wp_unique_filename",
        "intval", "absint", "floatval",
        "wp_verify_nonce", "check_admin_referer", "check_ajax_referer",
        "current_user_can",
        "wpdb->prepare",
    )

    # Sink evidence required before a finding in these categories is emitted. A category
    # absent from this table is never gated: for Broken Access Control the real sink lives
    # in a separately-named callback body, not on the registration line that matched, so
    # gating it suppresses 99% of the scanner's best class.
    #
    # A gate only adds information when the rule's own pattern does not already contain the
    # sink. LFI is the counter-example and has no entry here: the rule matches `include`, the
    # sink regex would be `include`, and the enclosing span always contains the matched line —
    # provably a no-op. Measured 541 -> 540 over 222 plugins before the entry was removed.
    SINKS = {
        "SQL Injection": re.compile(
            # A bare `$wpdb` used to count as a sink. It is not one: `$wpdb->insert/update/
            # delete/replace` build their own prepared statement and escape every value against
            # the column format, and `global $wpdb;` proves nothing at all. 24 of 80 SQLi
            # findings on the fresh corpus survived on it alone -- 22 in scopes whose only
            # `$wpdb` use was the escaping API, one on `$wpdb->db_version()`, one on a comment
            # that mentioned `$wpdb`. Zero were real. A method that takes a SQL string still
            # matches below, whether the string is built on that line or three lines up.
            r"->\s*(query|get_var|get_row|get_col|get_results|prepare)\s*\("
            r"|\bmysqli?_query\s*\("
            # Statement-shaped, not bare keywords: `\bSELECT\b` alone also matches the
            # HTML tag `<select>`, which kept 632/1426 findings alive on nothing.
            r"|\bSELECT\b[\s\S]{0,200}?\bFROM\b|\bUPDATE\b[\s\S]{0,200}?\bSET\b"
            r"|\bINSERT\s+INTO\b|\bDELETE\s+FROM\b|\bREPLACE\s+INTO\b|\bTRUNCATE\s+TABLE\b",
            re.IGNORECASE),
        "Server-Side Request Forgery (SSRF)": re.compile(
            r"\bwp_remote_\w+\s*\(|\bcurl_(exec|init|setopt)\s*\("
            r"|\b(file_get_contents|fsockopen|fopen)\s*\("),
        "PHP Object Injection": re.compile(r"\b(maybe_)?unserialize\s*\("),
        "Arbitrary File Read": re.compile(
            r"\b(file_get_contents|readfile|fread|fgets|fgetcsv|highlight_file|show_source|file)\s*\("
            r"|\bSplFileObject\b"),
        "Arbitrary File Deletion": re.compile(r"\b(unlink|wp_delete_file|rmdir)\s*\("),
        # Reading `$_FILES` is not the bug -- writing what it points at is. The rule's own
        # text was "verify file type validation", a hedge, and all 14 findings on the fresh
        # corpus were scopes that never wrote the upload at all: CSV parsers reading
        # `tmp_name`, and one handler that whitelists the mime type and hands the file to
        # `media_handle_sideload()`. `wp_handle_upload`/`media_handle_upload` are deliberately
        # absent: WordPress rejects dangerous extensions inside them, so routing an upload
        # through one is the fix. ponytail: a scope that only forwards `$_FILES` to another
        # function that writes it is missed, the same one-hop ceiling as every other gate.
        "Arbitrary File Upload": re.compile(
            r"\bmove_uploaded_file\s*\(|\b(?:copy|rename|file_put_contents|fwrite)\s*\("
            r"|->\s*extractTo\s*\("),
        "Open Redirect": re.compile(
            r"\bwp_(safe_)?redirect\s*\(|\bheader\s*\(\s*['\"]\s*Location\s*:"),
        "Privilege Escalation": re.compile(
            r"\b(update_option|add_option|update_site_option|update_user_meta|add_user_meta"
            r"|wp_insert_user|wp_create_user|wp_update_user|wp_set_password"
            r"|wp_set_auth_cookie|wp_set_current_user)\s*\("
            r"|->\s*(set_role|add_role|add_cap)\s*\("),
    }

    # Output escapers only prove safety for the category whose sink is output. Every other
    # rule keeps its finding unless the value was cast to a number.
    DEFAULT_SAFE = NUMERIC_SAFE | NONCE_SAFE
    ESCAPERS = {"Cross-Site Scripting (XSS)": DEFAULT_SAFE | OUTPUT_SAFE}
    # What has to be proven escaped, per category. Default: every superglobal on the line.
    SPOTS = {"Cross-Site Scripting (XSS)": XSS_SPOT}

    # A nopriv registration is a finding only when the handler it names checks nothing.
    # Measured over 100 plugins: 235 registrations, and 77% of the ones whose callback body
    # resolves guard inside that body. Unresolved callback -> emit, same as every other
    # fallback here: this can suppress only on positive evidence of a guard.
    GUARDS = re.compile(
        r"\b(current_user_can|current_user_can_for_blog|user_can|is_user_logged_in"
        r"|check_ajax_referer|check_admin_referer|wp_verify_nonce|wp_die)\s*\(")

    # A body that executes code is never suppressed, whatever the category. Unioned into
    # every gated check so a deprecated eval-equivalent cannot cause a false suppression;
    # this can only emit more, never suppress more.
    EXEC_SINK = re.compile(
        r"\b(eval|assert|create_function|system|exec|shell_exec|passthru|popen|proc_open)\s*\(")

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
        # (plugin, handler) already reported once. Keyed by plugin so two plugins that
        # happen to share a handler name still get one finding each.
        self._seen_handlers: set[tuple[str, str]] = set()
        # (plugin, file, function start line, category) already reported once.
        self._seen_scopes: set[tuple[str, str, int, str]] = set()
        # Functions in the plugin being scanned whose body performs a capability check.
        # Rebuilt per plugin by scan_plugin(); empty when scan_file() is called directly.
        self._guarded: set[str] = set()
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

    # ponytail: one-hop function-span resolution, same ceiling as scripts/bac_scan.py.
    # Two-hop (handler -> helper -> sink) is a known miss; see hd-quiz-save-results-light.
    # Upgrade path is bac_scan's callback resolver, not a taint engine.
    # Brace matching is quote- and comment-aware but not heredoc-aware: a `{` inside a
    # <<<HEREDOC mis-spans that one function. Every consumer falls back to whole-file when a
    # span does not resolve, so the worst case is today's behaviour, never silence.
    @staticmethod
    def _match_body(text: str, pos: int) -> tuple[int, int] | None:
        """From just after `function name(`, return the {...} body offsets, or None."""
        depth = 0
        quote = None
        comment = None  # "//" for line comments, "/*" for block comments
        escaped = False
        body_start = -1
        for i in range(pos, len(text)):
            char = text[i]
            if comment:
                if comment == "//":
                    if char == "\n":
                        comment = None
                elif char == "/" and text[i - 1] == "*":
                    comment = None
                continue
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            # Comments before quotes: an apostrophe in `// don't` opened a string that never
            # closed, swallowing the rest of a 7,603-line file and losing 5 of its 136 bodies.
            if char == "#" or (char == "/" and text[i + 1:i + 2] == "/"):
                comment = "//"
            elif char == "/" and text[i + 1:i + 2] == "*":
                comment = "/*"
            elif char in ("'", '"'):
                quote = char
            elif char == "{":
                if body_start < 0:
                    body_start = i
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return body_start, i
            elif char == ";" and body_start < 0:
                return None  # abstract / interface declaration, no body
        return None

    @classmethod
    def _function_spans(cls, text: str) -> list[tuple[str, int, int]]:
        """[(name, start_line, end_line)] for every function body in the file."""
        line_starts = [0]
        line_starts.extend(i + 1 for i, char in enumerate(text) if char == "\n")
        spans = []
        for match in ANON_OK.finditer(text):
            body = cls._match_body(text, match.end())
            if body is None:
                continue
            spans.append((
                match.group(1),
                bisect.bisect_right(line_starts, body[0]),
                bisect.bisect_right(line_starts, body[1]),
            ))
        return spans

    @staticmethod
    def _enclosing_span(
        spans: list[tuple[str, int, int]], line: int
    ) -> tuple[str, int, int] | None:
        """Innermost span containing ``line``, or None when the line is at top level."""
        best = None
        for span in spans:
            if span[1] <= line <= span[2] and (best is None or span[1] > best[1]):
                best = span
        return best

    @staticmethod
    def _reaches_sink(
        lines: list[str], hit: int, start: int, end: int, sink: re.Pattern
    ) -> bool:
        """Does the value read on line ``hit`` still appear at a sink further down the span?

        The sink gate proves a sink exists in the same function, which was the whole of the
        first bug report against this scanner: "it matched `wp_unslash()` but the `+ SQL` half
        was never checked". This closes it -- taint the names assigned on the matched line,
        walk forward through assignments, and require a tainted name in the sink statement.
        46 of 77 gated findings on the fresh corpus never reached their sink; the two hand-read
        samples were `$phone` going only to `$wpdb->update()` and a `$post_id` that the file
        read never touched.

        ponytail: within one span, forward-only, propagating through assignment. A value
        laundered through a helper call is not followed -- same one-hop ceiling as the span
        resolution itself. Upgrade path is a real def-use graph, which is a different tool.
        """
        # The match is a line, but the unit of use is the statement it sits in. Twelve of the
        # survivors were one `'msg' => sanitize_key($_GET['msg']),` inside a multi-line array
        # literal being handed to `wp_safe_redirect(add_query_arg(...))`: no assignment on the
        # line, so a line-scoped trace had nothing to follow and kept every one of them.
        first = hit
        while first > start and not STMT_BREAK.search(lines[first - 2]):
            first -= 1
        last = hit
        while last < end and ";" not in lines[last - 1]:
            last += 1
        stmt = "\n".join(lines[first - 1:last])

        tainted = set(ASSIGN.findall(stmt))
        if not tainted:
            # Used inline: this statement is the whole use site, so it is a lead only if the
            # statement is itself the sink.
            return bool(sink.search(stmt))
        pending = None  # name of an assignment whose statement runs past its own line
        for n in range(last + 1, end + 1):
            line = lines[n - 1]
            if sink.search(line):
                # A sink call's arguments often run onto the next lines.
                if tainted & set(VAR_NAME.findall("\n".join(lines[n - 1:min(end, n + 2)]))):
                    return True
            names = ASSIGN.findall(line)
            if names:
                pending = names[-1]
                if tainted & set(VAR_NAME.findall(line.split("=", 1)[1])):
                    tainted.add(pending)
            elif pending and tainted & set(VAR_NAME.findall(line)):
                # `$sql = "SELECT ...` on one line, the interpolated value on the next.
                tainted.add(pending)
            if ";" in line:
                pending = None
        return False

    @staticmethod
    def _callback_exposure(content: str) -> dict[str, str]:
        """Handler function name -> exposure label, taken from its registration site."""
        out: dict[str, str] = {}
        for hook, callback in CALLBACK_REG.findall(content):
            label = (
                "Unauthenticated" if hook == "wp_ajax_nopriv_"
                else "Authenticated (Subscriber+)"
            )
            if label == "Unauthenticated" or callback not in out:
                out[callback] = label
        return out

    def _nearby_sanitization(
        self,
        lines: list[str],
        line_num: int,
        window: int = 20,
        span: tuple[str, int, int] | None = None,
    ) -> list[str]:
        if span is not None:
            start, end = span[1] - 1, span[2]
        else:
            start = max(0, line_num - window - 1)
            end = min(len(lines), line_num + window)
        chunk = "\n".join(lines[start:end])
        # Word-boundary, not substring: `my_intval_helper` is not a call to intval().
        return [
            func for func in self.SAFE_FUNCS
            if re.search(rf"\b{re.escape(func)}\b", chunk)
        ]

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
        # Only rebuild lines that actually hold a guard call -- a substring test is ~13%
        # of the scan's wall clock cheaper than running the regex over every line.
        probes = [
            _probe(line) if ("isset" in line or "empty" in line or "array_key_exists" in line)
            else line
            for line in lines
        ]
        file_auth = self._file_auth_context(content)
        spans = self._function_spans(content)
        exposure = self._callback_exposure(content)

        try:
            rel_path = str(filepath.relative_to(self.extract_dir))
        except ValueError:
            rel_path = str(filepath)

        for vuln_type, config in self.VULN_PATTERNS.items():
            severity = config["severity"]
            for pattern, description in config["patterns"]:
                compiled = re.compile(pattern, re.IGNORECASE)
                for i, line in enumerate(lines, 1):
                    if not compiled.search(probes[i - 1]):
                        continue

                    # A match inside a comment is never a vulnerability. 10/844 findings over
                    # 100 plugins sat on one, including a `@see \ZipArchive::extractTo()` docblock
                    # reported CRITICAL.
                    if COMMENT_LINE.match(line):
                        continue

                    # Already escaped on this very line -- the remediation, not the bug.
                    if _all_escaped(probes[i - 1],
                                    self.ESCAPERS.get(vuln_type, self.DEFAULT_SAFE),
                                    self.SPOTS.get(vuln_type, SUPERGLOBAL)):
                        continue

                    span = self._enclosing_span(spans, i)
                    scope = (
                        "\n".join(lines[span[1] - 1:span[2]]) if span is not None
                        else content
                    )

                    sink = self.SINKS.get(vuln_type)
                    if sink is not None:
                        if not (sink.search(scope) or self.EXEC_SINK.search(scope)):
                            continue
                        if not self._reaches_sink(
                                lines, i,
                                span[1] if span is not None else 1,
                                span[2] if span is not None else len(lines), sink):
                            continue

                    if vuln_type == "Broken Access Control":
                        handler = None
                        if "wp_ajax_nopriv_" in line:
                            cb = CALLBACK_REG.search(line)
                            handler = cb.group(2) if cb else None
                        elif "permission_callback" in line:
                            # Nearest wins: one function usually registers several routes,
                            # so the first `callback` key in the window is often the
                            # previous route's. 45 of 51 sit within 8 lines of their key.
                            near = sorted(
                                (j for j in range(max(1, i - 8), min(len(lines), i + 8) + 1)
                                 if REST_CB.search(lines[j - 1])),
                                key=lambda j: abs(j - i))
                            handler = REST_CB.search(lines[near[0] - 1]).group(1) if near else None

                        if handler is not None:
                            # Same file first, then the plugin-wide index. Absence from both is
                            # not evidence -- an unresolvable handler still emits.
                            body = next((s for s in spans if s[0] == handler), None)
                            if body and self.GUARDS.search(
                                    "\n".join(lines[body[1] - 1:body[2]])):
                                continue
                            if handler in self._guarded:
                                continue

                            # One handler bound to 52 hook names is one lead, not 52.
                            # echo-knowledge-base alone was 52 of the 206 findings here.
                            if (plugin_name, handler) in self._seen_handlers:
                                continue
                            self._seen_handlers.add((plugin_name, handler))

                    # One vulnerable function is one lead. houzez-property-feed's
                    # save_import_settings reads 37 request fields into one query builder and
                    # produced 37 SQL Injection findings; a triager opens that function once.
                    # 214 of 466 findings over 100 plugins were repeats of this shape.
                    # Broken Access Control is excluded: it already dedups by handler name, and
                    # one registration function legitimately binds many distinct handlers.
                    if vuln_type != "Broken Access Control":
                        # Start line, not name -- two classes in one file may share a method name.
                        scope_key = (plugin_name, rel_path,
                                     span[1] if span is not None else -i, vuln_type)
                        if scope_key in self._seen_scopes:
                            continue
                        self._seen_scopes.add(scope_key)

                    # Broken Access Control matches the registration statement itself, so
                    # file scope is already the right scope for it.
                    if span is None or vuln_type == "Broken Access Control":
                        auth = file_auth
                    elif span[0] in exposure:
                        auth = exposure[span[0]]
                    else:
                        auth = self._file_auth_context(scope)

                    nearby_safe = self._nearby_sanitization(lines, i, span=span)
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

    def _guarded_functions(self, plugin_dir: Path) -> set[str]:
        """Names of functions anywhere in the plugin whose body performs a capability check.

        The WordPress Plugin Boilerplate registers hooks in `includes/class-*.php` and defines the
        handlers in `public/class-*-public.php`, so a same-file lookup resolves none of them: of the
        27 nopriv findings whose handler is named in the `$obj, 'method'` loader form, **0** resolve
        in the matched file and **26** guard when the whole plugin is searched. Only names are kept,
        not bodies -- a set of strings per plugin rather than its source.
        """
        guarded: set[str] = set()
        unguarded: set[str] = set()
        for php_file in self._iter_php_files(plugin_dir):
            try:
                text = php_file.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            # Cheap reject: no capability check anywhere in the file, so no body in it guards.
            # Names are enough here, and reading them off the declarations skips the brace
            # matching that dominates this pass -- most files in a plugin take this branch.
            if not self.GUARDS.search(text):
                unguarded.update(FUNC_DECL.findall(text))
                continue
            lines = text.split("\n")
            for name, start, end in self._function_spans(text):
                bucket = (guarded if self.GUARDS.search("\n".join(lines[start - 1:end]))
                          else unguarded)
                bucket.add(name)
        # The index is keyed by name, not by class, so a name defined twice proves nothing unless
        # every definition guards -- 141 of 4,348 duplicated names over 100 plugins disagree.
        return guarded - unguarded

    def scan_plugin(self, plugin_dir: Path) -> None:
        plugin_name = plugin_dir.name
        self._guarded = self._guarded_functions(plugin_dir)
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
