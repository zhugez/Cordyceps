<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-brightgreen?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-blue?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/openclaw-skill-purple?style=for-the-badge" alt="OpenClaw Skill"/>
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

**Cordyceps** is an [OpenClaw](https://docs.openclaw.ai) skill that automates the process of:

1. **Harvesting** popular WordPress plugins (10k+ active installs) using the [Mycelium](https://github.com/zhugez/Mycelium) bulk downloader
2. **Scanning** their PHP source code for 17 categories of security vulnerabilities
3. **Reporting** findings with severity ratings, CVSS estimates, and remediation advice

Named after the parasitic fungus from *The Last of Us* -- just as Cordyceps finds and takes over its host, this tool finds the vulnerabilities taking over WordPress plugins.

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

## Architecture

```
                    +------------------+
                    |   WordPress.org  |
                    |    Plugin API    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |    MYCELIUM      |     Rust-powered bulk downloader
                    |  (Harvester)     |     Filters by active installs
                    +--------+---------+
                             |
                    +--------v---------+
                    |   wp_extracted/   |     Extracted plugin source code
                    |   +-- plugin-a/  |
                    |   +-- plugin-b/  |
                    |   +-- plugin-c/  |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
     +--------v---------+         +--------v---------+
     |   scanner.py     |         |    scan.sh       |
     | (Python Engine)  |         | (Bash/ripgrep)   |
     | Context-aware    |         | Fast pattern     |
     | CVSS scoring     |         | matching         |
     | Auth detection   |         |                  |
     +--------+---------+         +--------+---------+
              |                             |
              +--------------+--------------+
                             |
              +--------------v--------------+
              |     VULNERABILITY REPORT    |
              |  +-- vuln_report.md         |
              |  +-- vuln_report.json       |
              |  +-- vuln_report.csv        |
              +-----------------------------+
```

---

## Quick Start

### Installation

#### As OpenClaw Skill (Recommended)

```bash
# Clone to OpenClaw skills directory
git clone https://github.com/zhugez/cordyceps.git ~/.openclaw/skills/cordyceps

# Setup Mycelium binary
# Linux:
chmod +x ~/.openclaw/skills/cordyceps/mycelium-linux-amd64
sudo cp ~/.openclaw/skills/cordyceps/mycelium-linux-amd64 /usr/local/bin/mycelium

# Windows (PowerShell):
copy $env:USERPROFILE\.openclaw\skills\cordyceps\mycelium-windows-amd64.exe $env:USERPROFILE\mycelium.exe
```

#### Standalone Usage

```bash
git clone https://github.com/zhugez/cordyceps.git
cd cordyceps
chmod +x mycelium-linux-amd64  # or use mycelium-windows-amd64.exe
```

---

### Usage

#### Full Pipeline (Harvest + Scan)

```bash
# Download plugins with 10k+ active installs, then scan
python scanner.py all --min-active 10000 --pages 5 -f md json csv
```

#### Step by Step

```bash
# Step 1: Preview targets
mycelium --min-active 10000 --pages 3 --list-only

# Step 2: Harvest & extract plugins
mycelium --min-active 10000 --pages 10 --extract --workers 10

# Step 3: Scan with Python engine (detailed analysis)
python scanner.py scan -d wp_extracted -r cordyceps_report -f md json csv

# Step 3 (alt): Quick scan with Bash script
bash scan.sh scan
```

#### Quick Bash Scan

```bash
# Full pipeline via bash
bash scan.sh all

# Environment variable overrides
MIN_ACTIVE=50000 PAGES=20 bash scan.sh all
```

---

## Output Formats

| Format | File | Best For |
|--------|------|----------|
| **Markdown** | `vuln_report.md` | Human-readable reports, presentations |
| **JSON** | `vuln_report.json` | Programmatic processing, CI/CD integration |
| **CSV** | `vuln_report.csv` | Spreadsheet analysis, data science |

### Sample Report Output

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
  SSRF:                      1

  TOTAL: 357 potential vulnerabilities
============================================================
```

---

## File Structure

```
cordyceps/
|
|-- SKILL.md                      # OpenClaw skill definition (17 vuln types)
|-- scanner.py                    # Python scanner engine (context-aware)
|-- scan.sh                       # Bash scanner (fast ripgrep-based)
|-- mycelium-linux-amd64          # Mycelium binary (Linux x86_64)
|-- mycelium-windows-amd64.exe    # Mycelium binary (Windows x86_64)
+-- README.md                     # This file
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
# Download subcommand
python scanner.py download [-m MIN] [-p PAGES] [--per-page N] [-w WORKERS] \
                            [-o DIR] [-e DIR] [-c CSV] [--list-only]

# Scan subcommand
python scanner.py scan [-d EXTRACT_DIR] [-r REPORT_NAME] [-f {md,json,csv} ...]

# All-in-one
python scanner.py all [all download + scan options combined]
```

---

## Knowledge Base Sources

| Source | Coverage | URL |
|--------|----------|-----|
| **Patchstack Academy** | 17 vulnerability types with WordPress-specific patterns | [patchstack.com/academy](https://patchstack.com/academy/wordpress/vulnerabilities/) |
| **Mycelium** | WordPress.org plugin API bulk downloader | [github.com/zhugez/Mycelium](https://github.com/zhugez/Mycelium) |
| **OpenClaw** | AI agent skill framework | [docs.openclaw.ai](https://docs.openclaw.ai/tools/skills) |

---

## False Positive Awareness

Not all findings are true vulnerabilities. Key context to consider:

| What Looks Dangerous | Why It Might Be Safe |
|---------------------|---------------------|
| `$wpdb->query()` with `$_POST` | Properly wrapped in `$wpdb->prepare()` with `%s`/`%d` |
| `$_GET` in SQL inside WP hooks | WordPress magic quotes auto-protect (unless `wp_unslash()` used) |
| `sanitize_text_field()` before SQL | Prevents XSS but NOT SQLi -- still needs `prepare()` |
| `move_uploaded_file()` | May have proper extension whitelist check before it |
| `wp_redirect()` | May be using hardcoded/validated URL, not user input |

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-vuln-pattern`)
3. Add new detection patterns to `SKILL.md` and `scanner.py`
4. Test against real WordPress plugins
5. Submit a Pull Request

---

## Disclaimer

This tool is intended for **authorized security testing and research only**. Always obtain proper authorization before scanning third-party WordPress installations. The authors are not responsible for any misuse of this tool.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>Part of the Mycelium Ecosystem</strong><br/>
  <a href="https://github.com/zhugez/Mycelium">Mycelium</a> (Harvester) |
  <strong>Cordyceps</strong> (Scanner)
</p>

<p align="center">
  <em>Built with fungal precision for the WordPress security community</em>
</p>
