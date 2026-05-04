"""Smoke tests for the Cordyceps scanner.

Tests use repository-rooted PHP fixtures. The scanner is invoked through its
public API where possible (fast assertions, clean stack traces) and through
``scanner.py`` as a subprocess for exit-code checks.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from scanner import PatchstackScanner  # noqa: E402

FIXTURES = REPO_ROOT / "tests" / "fixtures"
VULN_DIR = FIXTURES / "vulnerable_plugin"
SAFE_DIR = FIXTURES / "safe_plugin"


def _scan(extract_dir: Path) -> PatchstackScanner:
    scanner = PatchstackScanner(str(extract_dir), report_file="ignored", quiet=True)
    scanner.scan_all()
    return scanner


def test_finds_sqli_in_vulnerable_fixture(tmp_path: Path) -> None:
    shutil.copytree(VULN_DIR, tmp_path / "vulnerable_plugin")
    scanner = _scan(tmp_path)
    types = {f.vuln_type for f in scanner.findings}
    assert "SQL Injection" in types, f"Expected SQL Injection, got {types}"


def test_finds_xss_in_vulnerable_fixture(tmp_path: Path) -> None:
    shutil.copytree(VULN_DIR, tmp_path / "vulnerable_plugin")
    scanner = _scan(tmp_path)
    types = {f.vuln_type for f in scanner.findings}
    assert any("XSS" in t or "Scripting" in t for t in types), f"Expected XSS, got {types}"


def test_no_critical_findings_in_safe_plugin(tmp_path: Path) -> None:
    shutil.copytree(SAFE_DIR, tmp_path / "safe_plugin")
    scanner = _scan(tmp_path)
    criticals = [f for f in scanner.findings if f.severity == "CRITICAL"]
    assert criticals == [], (
        "Safe plugin should not produce CRITICAL findings: "
        + ", ".join(f"{f.vuln_type} @ {f.file}:{f.line}" for f in criticals)
    )


def test_skips_vendor_directory(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugin_with_vendor"
    plugin_dir.mkdir()
    vendor = plugin_dir / "vendor" / "thirdparty"
    vendor.mkdir(parents=True)
    shutil.copy(VULN_DIR / "sqli.php", vendor / "sqli.php")
    scanner = _scan(tmp_path)
    assert scanner.findings == [], (
        "vendor/ contents must be skipped; got: "
        + ", ".join(f"{f.vuln_type} @ {f.file}:{f.line}" for f in scanner.findings)
    )


def test_fail_on_critical_exits_nonzero(tmp_path: Path) -> None:
    shutil.copytree(VULN_DIR, tmp_path / "vulnerable_plugin")
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scanner.py"),
        "scan",
        "-d", str(tmp_path),
        "-r", str(tmp_path / "report"),
        "-f", "json",
        "--fail-on", "critical",
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0, (
        f"Expected non-zero exit when criticals present.\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
    )


def test_fail_on_never_exits_zero(tmp_path: Path) -> None:
    shutil.copytree(VULN_DIR, tmp_path / "vulnerable_plugin")
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scanner.py"),
        "scan",
        "-d", str(tmp_path),
        "-r", str(tmp_path / "report"),
        "-f", "json",
        "--fail-on", "never",
        "--quiet",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"Expected exit 0 with --fail-on never; got {result.returncode}.\n"
        f"stderr={result.stderr!r}"
    )
