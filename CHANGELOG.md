# Changelog

All notable changes to Cordyceps follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-05-04

### Added
- **Hermes Agent runtime support.** `SKILL.md` now ships dual `metadata.openclaw`
  and `metadata.hermes` blocks; the skill installs into
  `~/.hermes/skills/security/cordyceps/` on Hermes hosts.
- `install.sh` (POSIX) and `install.ps1` (Windows PowerShell) install scripts.
  Auto-detect runtime, fetch the latest Mycelium binary from
  `https://api.github.com/repos/zhugez/Mycelium/releases/latest`.
- `--fail-on {critical,high,medium,low,never}` flag on `scanner.py` for CI
  pipelines (non-zero exit when a finding at or above the threshold is found).
- `--quiet` flag on `scanner.py` to silence per-plugin progress lines.
- `pyproject.toml` declaring Python ≥3.9, ruff/pytest configuration, and a
  `cordyceps` console entry point.
- `tests/` directory with positive and negative PHP fixtures and a pytest suite.
- GitHub Actions CI matrix (Linux/Windows × Python 3.9/3.11/3.12) plus a
  `scan.sh` smoke job.
- `SECURITY.md`, `CONTRIBUTING.md`, this `CHANGELOG.md`.

### Changed
- `scanner.py` now caches each PHP file's content per scan (one read instead
  of three) and computes auth context once per file, dramatically reducing I/O
  on plugins with many findings.
- `scan_plugin()` now skips `vendor/`, `node_modules/`, `tests/`, `.git/`,
  `.svn/`, `dist/`, and `build/` directories to cut false positives from
  Composer dependencies and bundled tooling.
- Mycelium discovery paths in both `scanner.py` and `scan.sh` now use the
  `cordyceps/` subdirectory (was incorrectly `wp-vuln-scanner/`) and include
  the new Hermes paths.
- Mycelium is fetched at install time rather than committed to the repository
  (saves ~14 MB).
- Reports identify the scanner as `cordyceps` rather than the legacy
  `wp-vuln-scanner` name.

### Fixed
- Mycelium binary was never discovered via the documented OpenClaw install
  path because `find_mycelium()` looked under `wp-vuln-scanner/` while
  `SKILL.md` installed to `cordyceps/`.
- `scan.sh` grep fallback (used when ripgrep is not installed) crashed
  because it kept passing ripgrep-only `--type php`.
- Removed the dead "safe pattern marker" entry from the `Type Juggling` rules
  that filtered at scan time but bloated the regex set.
- `scan.sh` now respects `NO_COLOR` and disables ANSI codes when stdout is
  not a TTY.

### Removed
- Bundled `mycelium-linux-amd64` and `mycelium-windows-amd64.exe` binaries
  (replaced by download-on-install).

## [1.0.0]

### Added
- Initial release. Patchstack-based static scanner with 17 vulnerability
  categories. OpenClaw skill manifest. Mycelium-driven plugin harvest pipeline.
