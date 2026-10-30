<p align="center">
  <img src="https://img.shields.io/badge/version-1.1.0-brightgreen?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-blue?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-GPL--3.0-orange?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/runtime-OpenClaw%20%7C%20Hermes-purple?style=for-the-badge" alt="Runtimes"/>
  <img src="https://img.shields.io/badge/spec-agentskills.io-lightgrey?style=for-the-badge" alt="agentskills.io"/>
</p>

<h1 align="center">

```
   ██████╗ ██████╗ ██████╗ ██████╗ ██╗   ██╗ ██████╗███████╗██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗██╔════╝
  ██║     ██║   ██║██████╔╝██║  ██║ ╚████╔╝ ██║     █████╗  ██████╔╝███████╗
  ██║     ██║   ██║██╔══██╗██║  ██║  ╚██╔╝  ██║     ██╔══╝  ██╔═══╝ ╚════██║
  ╚██████╗╚██████╔╝██║  ██║██████╔╝   ██║   ╚██████╗███████╗██║     ███████║
   ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝    ╚═╝    ╚═════╝╚══════╝╚═╝     ╚══════╝
```

</h1>

<h3 align="center">
  <em>The parasitic fungus that finds what's taking over your WordPress</em>
</h3>

<p align="center">
  <strong>Automated WordPress Plugin Vulnerability Scanner</strong><br/>
  Powered by <a href="https://github.com/zhugez/Mycelium">Mycelium</a> + <a href="https://patchstack.com/academy/wordpress/vulnerabilities/">Patchstack Academy</a>
</p>

---

## What is Cordyceps?

**Cordyceps** is an [agentskills.io](https://agentskills.io) skill - works with both
[OpenClaw](https://docs.openclaw.ai) and [Hermes Agent](https://github.com/nousresearch/hermes-agent) -
that automates:

1. **Harvesting** popular WordPress plugins (10k+ active installs) using the [Mycelium](https://github.com/zhugez/Mycelium) bulk downloader
2. **Scanning** their PHP source code for 17 categories of security vulnerabilities
3. **Reporting** findings with severity ratings, CVSS estimates, and remediation advice

Named after the parasitic fungus from *The Last of Us* - just as Cordyceps finds and takes over its host, this tool finds the vulnerabilities taking over WordPress plugins.

---

## Vulnerability Coverage

Cordyceps detects **17 vulnerability categories** based on the [Patchstack Academy](https://patchstack.com/academy/wordpress/vulnerabilities/) knowledge base:

| # | Category | Severity | Detection Method |
|:-:|----------|:--------:|-----------------|
| 1 | **SQL Injection** | `CRITICAL` | `$wpdb->query()` with unsanitized input, `wp_unslash()` + SQL, `%1s` bypass |
| 2 | **Cross-Site Scripting (XSS)** | `HIGH` | 6 sub-types: Shortcode, Gutenberg, Elementor, Reflected, Query Arg, Admin Notice |
| 3 | **CSRF** | `MEDIUM` | State-changing hooks without `wp_verify_nonce()` |
| 4 | **Arbitrary File Upload** | `CRITICAL` | `move_uploaded_file()`, `test_type => false`, ZIP extraction, MIME bypass |
| 5 | **Broken Access Control** | `HIGH` | `__return_true` permission, `wp_ajax_nopriv_`, nonce leakage |
| 6 | **PHP Object Injection** | `CRITICAL` | `unserialize()` / `maybe_unserialize()` with user input |
| 7 | **Local File Inclusion** | `CRITICAL` | `include`/`require` with user-controlled paths |
| 8 | **Remote Code Execution** | `CRITICAL` | `eval()`, `system()`, `call_user_func()`, dynamic calls |
| 9 | **SSRF** | `HIGH` | `wp_remote_get()` with user-controlled URLs |
| 10 | **Privilege Escalation** | `CRITICAL` | `update_option()` key control, `wp_set_auth_cookie()`, role manipulation |
| 11 | **Sensitive Data Exposure** | `MEDIUM` | Unprotected `get_post()`, predictable log files |
| 12 | **Open Redirect** | `MEDIUM` | `wp_redirect()` without `wp_safe_redirect()` |
| 13 | **Arbitrary File Read** | `HIGH` | `file_get_contents()` / `readfile()` with traversal |
| 14 | **Arbitrary File Deletion** | `HIGH` | `unlink()` / `wp_delete_file()` with user paths |
| 15 | **Content Injection** | `MEDIUM` | `do_shortcode()` with user input, unauthorized `wp_update_post()` |
| 16 | **Race Condition** | `MEDIUM` | TOCTOU gaps in financial/limit operations |
| 17 | **Type Juggling** | `MEDIUM` | `==` instead of `===` for security comparisons |

---

## Quick Start

### Installation

The installer auto-detects your runtime (OpenClaw or Hermes), downloads the
matching Mycelium binary from the latest GitHub release, and wires the skill
into the right directory.

#### POSIX (Linux / macOS)

```bash
git clone https://github.com/zhugez/cordyceps.git
cd cordyceps
bash install.sh                       # auto-detect runtime
# bash install.sh --runtime openclaw  # force OpenClaw
# bash install.sh --runtime hermes    # force Hermes
# bash install.sh --skip-binary       # don't download Mycelium
```

#### Windows (PowerShell)

```powershell
git clone https://github.com/zhugez/cordyceps.git
Set-Location cordyceps
.\install.ps1                         # auto-detect runtime
# .\install.ps1 -Runtime openclaw
# .\install.ps1 -Runtime hermes
# .\install.ps1 -SkipBinary
```

#### Standalone (no agent)

```bash
git clone https://github.com/zhugez/cordyceps.git
cd cordyceps
pip install -e .
bash install.sh --skip-binary         # creates ./mycelium symlink scope only
# or fetch Mycelium manually:
# curl -L https://github.com/zhugez/Mycelium/releases/latest/download/mycelium-linux-amd64 -o mycelium
# chmod +x mycelium
cordyceps scan -d wp_extracted
```

#### Skill location after install

| Runtime  | Path |
|----------|------|
| OpenClaw | `~/.openclaw/skills/cordyceps/` |
| Hermes   | `~/.hermes/skills/security/cordyceps/` |

Override the home directory with `OPENCLAW_HOME` / `HERMES_HOME` if you use
non-default locations.

---

### Usage

#### Full pipeline (harvest + scan)

```bash
# Download plugins with 10k+ active installs, then scan
python scanner.py all --min-active 10000 --pages 5 -f md json csv
```

#### Step by step

```bash
# 1. Preview targets
python scanner.py download --min-active 10000 --pages 3 --list-only

# 2. Harvest & extract
python scanner.py download --min-active 10000 --pages 10 -w 10

# 3. Scan
python scanner.py scan -d wp_extracted -r cordyceps_report -f md json csv

# 3 (alt). Quick scan with bash
bash scan.sh scan
```

#### CI integration

```bash
python scanner.py scan -d wp_extracted --fail-on critical --quiet -f json
# exits 1 if any CRITICAL finding exists; else 0
```

`--fail-on` accepts: `critical`, `high`, `medium`, `low`, `never` (default).

#### Bash quick-scan environment overrides

```bash
MIN_ACTIVE=50000 PAGES=20 NO_COLOR=1 bash scan.sh all
```

---

## Output Formats

| Format | File | Best For |
|--------|------|----------|
| **Markdown** | `vuln_report.md` | Human-readable reports |
| **JSON** | `vuln_report.json` | Programmatic processing, CI/CD |
| **CSV** | `vuln_report.csv` | Spreadsheet analysis |

### Sample summary

```
============================================================
SCAN SUMMARY
============================================================
  SQL Injection:          152
  Cross-Site Scripting:   134
  Local File Inclusion:    30
  Type Juggling:           17
  Broken Access Control:   10
  Arbitrary File Upload:    9
  Shortcode XSS:            4
  SSRF:                     1

  TOTAL: 357 potential vulnerabilities
============================================================
```

---

## File Structure

```
cordyceps/
+-- SKILL.md                # Skill manifest (dual: openclaw + hermes)
+-- scanner.py              # Python scanner engine (context-aware)
+-- scan.sh                 # Bash quick-scan (rg/grep)
+-- install.sh              # POSIX installer (downloads Mycelium)
+-- install.ps1             # Windows installer
+-- pyproject.toml          # Python packaging + ruff/pytest config
+-- tests/                  # Unit + integration tests with PHP fixtures
+-- .github/workflows/      # CI: ruff + pytest matrix (Linux + Windows)
+-- README.md               # This file
+-- SECURITY.md             # Disclosure policy
+-- CONTRIBUTING.md         # Dev setup, pattern guidelines
+-- CHANGELOG.md            # Version history
```

Mycelium binaries are no longer bundled in the repo; the installer fetches the
latest release for your OS/arch. To pin a specific tag:

```bash
bash install.sh --mycelium-version v1.0.0
```

---

## Mycelium CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-m, --min-active <N>` | `10000` | Minimum active installs filter |
| `-p, --pages <N>` | `50` | API pages to fetch |
| `--per-page <N>` | `100` | Plugins per page |
| `-o, --output-dir <DIR>` | `wp_zips` | Download directory |
| `-w, --workers <N>` | `5` | Parallel download workers |
| `-c, --csv-path <PATH>` | `plugins.csv` | Plugin list CSV output |
| `--list-only` | `false` | Preview only, skip downloads |
| `-e, --extract` | `false` | Auto-extract ZIPs after download |
| `--extract-dir <DIR>` | `wp_extracted` | Extraction directory |

---

## Python Scanner Options

```bash
# Download
python scanner.py download [-m MIN] [-p PAGES] [--per-page N] [-w WORKERS] \
                            [-o DIR] [-e DIR] [-c CSV] [--list-only]

# Scan
python scanner.py scan [-d EXTRACT_DIR] [-r REPORT_NAME] [-f {md,json,csv} ...] \
                       [--fail-on {critical,high,medium,low,never}] [--quiet]

# All-in-one
python scanner.py all [download options] [scan options]
```

---

## Troubleshooting

| Symptom | Resolution |
|---------|-----------|
| `Mycelium binary not found` | Re-run the installer, or set `CORDYCEPS_MYCELIUM=/abs/path/to/mycelium`. |
| `ripgrep (rg) not found, falling back to grep` | Install ripgrep: `apt install ripgrep` / `brew install ripgrep` / `winget install BurntSushi.ripgrep.MSVC`. |
| Scanner reports 0 findings on a known-vulnerable plugin | Check that the plugin lives in a top-level subdirectory of `--extract-dir`, and isn't inside `vendor/` or `tests/` (those are skipped). |
| Windows `cmd.exe` shows raw `\033[…m` codes | Set `NO_COLOR=1` or run via PowerShell / Windows Terminal. |
| GitHub API rate limit during install | Set `GITHUB_TOKEN=<your_token>` before running `install.sh`. |

---

## Knowledge Base Sources

| Source | Coverage | URL |
|--------|----------|-----|
| **Patchstack Academy** | 17 vulnerability types with WordPress-specific patterns | [patchstack.com/academy](https://patchstack.com/academy/wordpress/vulnerabilities/) |
| **Mycelium** | WordPress.org plugin API bulk downloader | [github.com/zhugez/Mycelium](https://github.com/zhugez/Mycelium) |
| **OpenClaw** | AI agent skill framework | [docs.openclaw.ai](https://docs.openclaw.ai/tools/skills) |
| **Hermes Agent** | Agentic framework by NousResearch | [github.com/nousresearch/hermes-agent](https://github.com/nousresearch/hermes-agent) |
| **agentskills.io** | Open skill spec used by both runtimes | [agentskills.io](https://agentskills.io) |

---

## False Positive Awareness

Not all findings are true vulnerabilities. Key context to consider:

| What Looks Dangerous | Why It Might Be Safe |
|---------------------|---------------------|
| `$wpdb->query()` with `$_POST` | Properly wrapped in `$wpdb->prepare()` with `%s`/`%d` |
| `$_GET` in SQL inside WP hooks | WordPress magic quotes auto-protect (unless `wp_unslash()` used) |
| `sanitize_text_field()` before SQL | Prevents XSS but NOT SQLi - still needs `prepare()` |
| `move_uploaded_file()` | May have proper extension whitelist check before it |
| `wp_redirect()` | May be using hardcoded/validated URL, not user input |

---

## Contributing & Security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, pattern-writing
  guidelines, and the test layout.
- See [SECURITY.md](SECURITY.md) for the disclosure policy and supported scope.
- See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## Disclaimer

This tool is intended for **authorized security testing and research only**.
Always obtain proper authorization before scanning third-party WordPress
installations. The authors are not responsible for any misuse.

---

## License

GPL-3.0 - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Part of the Mycelium Ecosystem</strong><br/>
  <a href="https://github.com/zhugez/Mycelium">Mycelium</a> (Harvester) |
  <strong>Cordyceps</strong> (Scanner)
</p>

<p align="center">
  <em>Built with fungal precision for the WordPress security community</em>
</p>
