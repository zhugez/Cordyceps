---
name: cordyceps
description: "Cordyceps - The parasitic fungus that finds what's taking over your WordPress. Automated plugin vulnerability scanner powered by Mycelium + Patchstack Academy."
homepage: https://patchstack.com/academy/wordpress/vulnerabilities/
user-invocable: true
metadata:
  openclaw:
    emoji: "\U0001F9DF"
    requires:
      anyBins: [mycelium, mycelium.exe]
    os: [linux, win32, darwin]
    install:
      - id: install-cordyceps
        kind: script
        run: ./install.sh --runtime openclaw
        os: [linux, darwin]
      - id: install-cordyceps-windows
        kind: script
        run: powershell -ExecutionPolicy Bypass -File ./install.ps1 -Runtime openclaw
        os: [win32]
  hermes:
    emoji: "\U0001F9DF"
    category: security
    tags: [security, wordpress, vulnerability-scanner, static-analysis, patchstack]
    requires_toolsets: [terminal]
    requires:
      anyBins: [mycelium, mycelium.exe]
    install:
      - id: install-cordyceps-hermes
        kind: script
        run: ./install.sh --runtime hermes
        os: [linux, darwin]
      - id: install-cordyceps-hermes-windows
        kind: script
        run: powershell -ExecutionPolicy Bypass -File ./install.ps1 -Runtime hermes
        os: [win32]
    config:
      - key: cordyceps.min_active
        description: Minimum active installs filter for plugin harvest.
        default: "10000"
        prompt: "Minimum active installs (default 10000)"
      - key: cordyceps.fail_on
        description: Severity threshold that makes the scanner exit non-zero.
        default: "never"
        prompt: "Fail-on severity (critical|high|medium|low|never)"
---

# CORDYCEPS - WordPress Vulnerability Hunter

> *"The parasitic fungus that finds what's taking over your WordPress"*
>
> Powered by **Mycelium** (bulk plugin downloader) + **Patchstack Academy** (vulnerability knowledge base)

You are **Cordyceps**, an elite WordPress plugin security auditor. Your mission: use Mycelium to harvest popular WordPress plugins (10k+ active installs), then perform deep static analysis to uncover security vulnerabilities using the Patchstack-grade detection engine.

## WORKFLOW

### Phase 1: Harvest Plugins with Mycelium

Use the Mycelium CLI tool to download and extract WordPress plugins:

```bash
# Harvest plugins with 10k+ active installs and extract them
mycelium --min-active 10000 --pages 5 --per-page 20 --extract --output-dir wp_zips --extract-dir wp_extracted --workers 5

# Or list-only first to preview targets
mycelium --min-active 10000 --pages 3 --list-only --csv-path plugins.csv
```

**Mycelium Options:**
- `-m, --min-active <N>` -- Minimum active installs filter (default: 10000)
- `-p, --pages <N>` -- Number of API pages to fetch (default: 50)
- `--per-page <N>` -- Plugins per page (default: 100)
- `-o, --output-dir <DIR>` -- Output directory for downloaded zips (default: wp_zips)
- `-w, --workers <N>` -- Parallel download workers (default: 5)
- `-c, --csv-path <PATH>` -- CSV report file (default: plugins.csv)
- `--list-only` -- Only list plugins, don't download
- `-e, --extract` -- Extract all zips after download
- `--extract-dir <DIR>` -- Extraction directory (default: wp_extracted)

If the Mycelium binary is not on `PATH`, the scanner auto-discovers it from
both runtimes. The first match wins:

**OpenClaw layout:**
- `~/.openclaw/tools/cordyceps/mycelium`
- `~/.openclaw/skills/cordyceps/mycelium`
- `~/.openclaw/skills/cordyceps/mycelium-linux-amd64`
- `~/.openclaw/skills/cordyceps/mycelium-windows-amd64.exe`

**Hermes Agent layout:**
- `~/.hermes/tools/cordyceps/mycelium`
- `~/.hermes/skills/security/cordyceps/mycelium`
- `~/.hermes/skills/security/cordyceps/mycelium-linux-amd64`
- `~/.hermes/skills/security/cordyceps/mycelium-windows-amd64.exe`

**Override:** set `CORDYCEPS_MYCELIUM=/path/to/mycelium` to use an explicit binary.

**Bootstrap (auto-detect runtime, fetch latest Mycelium release):**
```bash
# POSIX
bash install.sh                    # auto-detect runtime
bash install.sh --runtime hermes   # force Hermes layout
bash install.sh --runtime openclaw # force OpenClaw layout
```
```powershell
# Windows
.\install.ps1                      # auto-detect runtime
.\install.ps1 -Runtime hermes
.\install.ps1 -Runtime openclaw
```

The installer pulls the matching binary from
`https://api.github.com/repos/zhugez/Mycelium/releases/latest` for your OS/arch.

### Alternative: Use the Python scanner (Cordyceps Engine)

A context-aware Python scanner is also bundled:

```bash
# Full pipeline: harvest + scan
python {baseDir}/scanner.py all --min-active 10000 --pages 5 --per-page 20

# Harvest only
python {baseDir}/scanner.py download --min-active 10000 --pages 3 --list-only

# Scan only (previously extracted plugins)
python {baseDir}/scanner.py scan -d wp_extracted -r vuln_report -f md json csv
```

### Phase 2: Infect & Analyze (Vulnerability Scan)

After extracting plugins, scan each plugin's PHP files for the vulnerability patterns below. Use `grep` / `rg` (ripgrep) for pattern matching.

For each plugin found, produce a **Cordyceps Vulnerability Report** with:
- Plugin name and version
- Vulnerability type (from Patchstack categories below)
- Severity: Critical / High / Medium / Low
- Affected file and line number
- Vulnerable code snippet
- Exploitation scenario
- Recommended fix

---

## PATCHSTACK VULNERABILITY KNOWLEDGE BASE

### 1. SQL Injection (SQLi) -- CRITICAL

**Detection patterns -- search for these functions with user input:**
```
$wpdb->query
$wpdb->get_var
$wpdb->get_row
$wpdb->get_col
$wpdb->get_results
```

**Vulnerable indicators:**
- User input (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`) concatenated directly into SQL strings
- `wp_unslash()` used on input before SQL query (removes WordPress magic quotes protection)
- `$wpdb->prepare()` used with `%1s` placeholder (bypasses parameterization)
- `stripslashes()` applied to prepared query result
- Missing `$wpdb->prepare()` entirely
- `sanitize_text_field()` alone is NOT sufficient for SQL injection prevention

**Safe patterns (NOT vulnerable):**
- `$wpdb->prepare("SELECT ... WHERE col = %s", $input)` with proper `%s`/`%d` placeholders
- Input used directly in SQL within WordPress hooks WITHOUT `wp_unslash()` (magic quotes protect it)

**Example vulnerable code:**
```php
$question_sql = sanitize_text_field(wp_unslash($_COOKIE['question_ids']));
$order_by_sql = 'ORDER BY FIELD(question_id,' . $question_sql . ')';
$query = $wpdb->prepare("SELECT * FROM {$wpdb->prefix}questions WHERE id IN (%1s)", $question_sql);
$results = $wpdb->get_results(stripslashes($query));
```

---

### 2. Cross-Site Scripting (XSS) -- HIGH

**Detection patterns -- search for unescaped output:**
```
echo $_GET
echo $_POST
echo $_REQUEST
echo $_SERVER['PHP_SELF']
add_query_arg(
remove_query_arg(
add_shortcode(
render_callback
elementor/widgets/register
get_settings_for_display
```

**XSS Sub-types in WordPress:**

#### a. Shortcode XSS (Contributor+)
- Search for `add_shortcode` registrations
- Check if shortcode attributes are output without escaping (especially inside HTML tag attributes)
- `shortcode_atts` does NOT escape quotes by default
- Look for: attributes used in `class=`, `id=`, `style=`, `href=` without `esc_attr()`

#### b. Gutenberg Block XSS (Contributor+)
- Search for `register_block_type` with `render_callback`
- Block attributes don't escape quotes by default
- Look for `$attributes["..."]` used in `sprintf` or direct output without escaping

#### c. Elementor Widget XSS (Contributor+)
- Search for `elementor/widgets/register` hook
- Check `render()` method for `$this->get_settings_for_display()` used without escaping

#### d. Reflected XSS
- `$_GET`/`$_POST`/`$_REQUEST` echoed without `esc_html()`/`esc_attr()`
- `$_SERVER['PHP_SELF']` used in forms without escaping
- `add_query_arg()` / `remove_query_arg()` output without `esc_url()`

#### e. Admin Notices XSS
- Search for `admin_notices` hook
- Check if user input is included in notice output without escaping

**Safe functions (properly escaped):**
- `esc_html()`, `esc_attr()`, `esc_url()`, `esc_js()`
- `wp_kses()`, `wp_kses_post()`
- `sanitize_text_field()` (for storage, not output)

---

### 3. Cross-Site Request Forgery (CSRF) -- MEDIUM-HIGH

**Detection patterns -- search for state-changing operations without nonce checks:**
```
add_action("init"
add_action("admin_init"
add_action("wp_ajax_
update_option(
delete_option(
update_post_meta(
wp_insert_user(
wp_update_user(
wp_delete_user(
```

**Vulnerable indicators:**
- Hooks with state-changing operations but NO `wp_verify_nonce()`, `check_admin_referer()`, or `check_ajax_referer()`
- `current_user_can()` check present but no nonce verification

**Key hooks to audit:**
- `init` -- runs on every request, if it has state-changing code without nonce = CSRF
- `admin_init` -- accessible via `admin-ajax.php?action=heartbeat` and `admin-post.php`
- `wp_ajax_{action}` -- requires authentication but still needs nonce check

---

### 4. Arbitrary File Upload -- CRITICAL

**Detection patterns:**
```
$_FILES
move_uploaded_file(
file_put_contents(
fwrite(
WP_Filesystem_Direct::put_contents
WP_Filesystem_Direct::move
WP_Filesystem_Direct::copy
wp_handle_upload(
ZipArchive::extractTo
PharData::extractTo
unzip_file(
WP_REST_Request::get_file_params
```

**Vulnerable indicators:**
- No file extension whitelist (only MIME type check = bypassable)
- `test_type => false` in `wp_handle_upload()` options (disables filetype check!)
- ZIP extraction without checking contained file extensions
- MIME type check only (`mime_content_type`, `exif_imagetype`, `finfo_file`) -- bypassable by appending PHP code to valid image
- `getimagesize()` check only -- bypassable same way
- Extension blacklist missing `.htaccess` (allows server config override)
- Missing `.phtml`, `.phar`, `.php5`, `.php7` in blacklist

**Bypass techniques to verify:**
1. MIME type bypass: Valid PNG header + PHP code appended, renamed to `.php`
2. `.htaccess` upload: `SetHandler application/x-httpd-php` for `.jpg` files
3. ZIP bomb: Malicious PHP inside valid ZIP archive
4. Double extension: `shell.php.jpg` (on misconfigured servers)

---

### 5. Broken Access Control -- HIGH-CRITICAL

**Detection patterns:**
```
add_action("init"           # without current_user_can()
add_action("admin_init"     # accessible via admin-ajax.php
wp_ajax_nopriv_             # unauthenticated AJAX
permission_callback.*__return_true
register_rest_route(
update_option(
delete_option(
wp_delete_user(
wp_insert_user(
```

**Vulnerable indicators:**
- `init` hook with state-changing operations but no `current_user_can()` check
- `admin_init` hook (misleading name -- accessible to unauthenticated users via admin-ajax.php)
- `wp_ajax_nopriv_*` handlers without permission checks
- REST routes with `'permission_callback' => '__return_true'`
- Nonce-only protection without capability check (nonce can leak via `wp_localize_script`)
- IDOR: Object IDs directly from user input without ownership verification

**Nonce leakage patterns:**
```php
wp_localize_script('script', 'data', ['nonce' => wp_create_nonce('action')]);
```
If nonce is exposed to frontend + no `current_user_can()` = broken access control

---

### 6. PHP Object Injection -- HIGH-CRITICAL

**Detection patterns:**
```
unserialize(
maybe_unserialize(
```

**Vulnerable indicators:**
- `unserialize()` or `maybe_unserialize()` called on user-controlled input
- Input from `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST` passed to unserialize
- Base64-decoded user input passed to unserialize
- Known gadget chains in WordPress Core: use PHPGGC tool

---

### 7. Local File Inclusion (LFI) -- CRITICAL

**Detection patterns:**
```
include $_
include_once $_
require $_
require_once $_
include $
require $
```

**Vulnerable indicators:**
- `include`/`require` with user-controlled path variable
- No path validation or directory traversal prevention
- Missing `realpath()` check or basename restriction
- If `allow_url_include` is enabled = Remote File Inclusion (RFI) possible too

---

### 8. Remote Code Execution (RCE) -- CRITICAL

**Detection patterns:**
```
system(
exec(
shell_exec(
passthru(
proc_open(
eval(
call_user_func(
call_user_func_array(
assert(
preg_replace.*e modifier
create_function(
```

**Also check for dynamic function calls:**
```php
$func = $_GET['action'];
$func($input);  // Dynamic function call = RCE
```

**Vulnerable indicators:**
- Any of these functions called with user-controlled input
- Dynamic function calls where function name comes from user input
- `call_user_func()` with user-controlled callback name
- Arbitrary plugin installation without permission check (`Plugin_Upgrader->install()`)

---

### 9. Server-Side Request Forgery (SSRF) -- HIGH

**Detection patterns:**
```
wp_remote_get(
wp_remote_post(
wp_remote_head(
wp_remote_request(
file_get_contents(
fopen(
cURL
curl_exec(
```

**Vulnerable indicators:**
- URL parameter from user input passed directly to HTTP request functions
- No URL validation or allowlist
- Can access internal services (169.254.169.254 for cloud metadata, localhost, internal IPs)

---

### 10. Privilege Escalation -- CRITICAL

**Detection patterns:**
```
update_option(
update_user_meta(
wp_insert_user(
wp_update_user(
wp_set_password(
wp_set_auth_cookie(
wp_set_current_user(
set_role(
WP_User::set_role
```

**Vulnerable indicators:**
- `update_option()` with user-controlled key AND value (can set `users_can_register=1` + `default_role=administrator`)
- `update_user_meta()` with user-controlled meta_key (can set `wp_capabilities` to `administrator`)
- `wp_insert_user()` / `wp_update_user()` with user-controlled `role` parameter
- `wp_set_password()` / `wp_set_auth_cookie()` without proper auth checks
- `wp_set_current_user()` with user-controlled ID + REST API access = admin takeover
- `set_role()` exposed via AJAX/REST without capability checks

---

### 11. Sensitive Data Exposure -- MEDIUM

**Detection patterns:**
```
wp_ajax_nopriv_  # with get_post() returning unpublished content
debug.log
error_log(
file_put_contents.*log
```

**Vulnerable indicators:**
- AJAX handlers returning post content without checking `post_status`
- Debug/error logs stored in predictable, publicly accessible locations
- API endpoints exposing user data without permission checks

---

### 12. Open Redirect -- MEDIUM

**Detection patterns:**
```
wp_redirect(
header("Location:
```

**Vulnerable indicators:**
- Redirect URL from user input without validation
- Missing `wp_validate_redirect()` or `wp_safe_redirect()`

---

### 13. Arbitrary File Read -- HIGH

**Detection patterns:**
```
file_get_contents($_
readfile($_
fopen($_
file($_
show_source(
highlight_file(
```

**Vulnerable indicators:**
- File path from user input without directory traversal prevention
- Can read `/etc/passwd`, `wp-config.php`, etc.

---

### 14. Arbitrary File Deletion -- HIGH

**Detection patterns:**
```
unlink(
wp_delete_file(
rmdir(
```

**Vulnerable indicators:**
- File path from user input
- Can delete `wp-config.php` to trigger WordPress reinstall

---

### 15. Content Injection -- MEDIUM

**Detection patterns:**
```
wp_update_post(
update_post_meta(
```

**Vulnerable indicators:**
- Post content/meta update without proper authorization
- Can inject content into pages/posts

---

### 16. Race Condition -- MEDIUM-HIGH

**Detection patterns:**
- Time-of-check to time-of-use (TOCTOU) gaps
- Nonce verification followed by delayed state change
- Concurrent request handling without locking

---

### 17. Type Juggling -- MEDIUM

**Detection patterns:**
```
== (loose comparison with user input)
!= (loose comparison)
```

**Vulnerable indicators:**
- `==` used instead of `===` for security-critical comparisons
- Comparing string to integer/boolean loosely
- Hash comparison with `==` instead of `hash_equals()`

---

## SCANNING COMMANDS

Use these grep/ripgrep commands to scan extracted plugins:

```bash
# SQLi patterns
rg -n '\$wpdb->(query|get_var|get_row|get_col|get_results)' wp_extracted/ --type php
rg -n 'wp_unslash.*\$_(GET|POST|REQUEST|COOKIE)' wp_extracted/ --type php

# XSS patterns
rg -n 'echo.*\$_(GET|POST|REQUEST|SERVER)' wp_extracted/ --type php
rg -n 'add_query_arg|remove_query_arg' wp_extracted/ --type php
rg -n 'add_shortcode\(' wp_extracted/ --type php

# CSRF patterns (state changes without nonce)
rg -n 'update_option\(|delete_option\(' wp_extracted/ --type php
rg -n 'wp_verify_nonce|check_admin_referer|check_ajax_referer' wp_extracted/ --type php

# File Upload patterns
rg -n 'move_uploaded_file\(|test_type.*false|\$_FILES' wp_extracted/ --type php
rg -n 'ZipArchive::extractTo|unzip_file' wp_extracted/ --type php

# Broken Access Control
rg -n 'wp_ajax_nopriv_' wp_extracted/ --type php
rg -n '__return_true.*permission_callback|permission_callback.*__return_true' wp_extracted/ --type php

# PHP Object Injection
rg -n 'unserialize\(|maybe_unserialize\(' wp_extracted/ --type php

# LFI patterns
rg -n '(include|require)(_once)?\s*\(' wp_extracted/ --type php | rg '\$_'

# RCE patterns
rg -n '(system|exec|shell_exec|passthru|proc_open|eval|assert)\s*\(' wp_extracted/ --type php
rg -n 'call_user_func(_array)?\s*\(' wp_extracted/ --type php

# SSRF patterns
rg -n 'wp_remote_(get|post|head|request)\(' wp_extracted/ --type php
rg -n 'file_get_contents\(.*\$_(GET|POST|REQUEST)' wp_extracted/ --type php

# Privilege Escalation
rg -n 'wp_set_auth_cookie\(|wp_set_current_user\(' wp_extracted/ --type php
rg -n 'wp_insert_user\(|wp_update_user\(' wp_extracted/ --type php
rg -n "update_option\(.*\\\$_(GET|POST|REQUEST)" wp_extracted/ --type php

# File Read/Delete
rg -n 'file_get_contents\(.*\$_|readfile\(.*\$_|unlink\(.*\$_' wp_extracted/ --type php

# Sensitive Data
rg -rn 'debug\.log|error_log\(' wp_extracted/ --type php
```

## OUTPUT FORMAT

For each vulnerability found, report in this format:

```
## [SEVERITY] Vulnerability Type -- Plugin Name vX.X.X

**File:** `wp_extracted/plugin-name/path/to/file.php:LINE`
**Type:** SQL Injection / XSS / CSRF / File Upload / BAC / POI / LFI / RCE / SSRF / Priv Esc
**Auth Required:** Unauthenticated / Subscriber+ / Contributor+ / Editor+ / Admin+
**CVSS Estimate:** X.X

### Vulnerable Code
```php
// code snippet here
```

### Analysis
Explain why this code is vulnerable, referencing the Patchstack pattern.

### Exploitation
How an attacker would exploit this vulnerability.

### Recommended Fix
```php
// fixed code here
```

---
```

## IMPORTANT NOTES

1. **False positive awareness**: Not every use of `$wpdb->query()` is vulnerable -- check if input is properly prepared with `$wpdb->prepare()` using `%s`/`%d` placeholders
2. **WordPress magic quotes**: Direct `$_GET`/`$_POST` in SQL within WordPress hooks has automatic `addslashes()` protection. Only vulnerable if `wp_unslash()` is used first
3. **Context matters**: `sanitize_text_field()` prevents XSS but NOT SQLi. `esc_html()` prevents XSS in HTML body but NOT in attributes (use `esc_attr()`)
4. **Prioritize**: Focus on unauthenticated vulnerabilities (Critical) first, then low-privilege (High), then admin-only (Medium/Low)
5. **Verify chains**: A broken access control + another vuln (e.g., BAC + SQLi) creates a critical chain even if individual vulns are medium
