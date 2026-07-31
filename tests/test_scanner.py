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


def test_csrf_category_is_gone() -> None:
    """The CSRF rules matched a hook registration, never a missing nonce. Deleted."""
    assert "CSRF" not in PatchstackScanner.VULN_PATTERNS


def test_esc_sql_is_not_treated_as_a_sanitizer(tmp_path: Path) -> None:
    """esc_sql() provides no quoting. A prefix rule over `esc_` would downgrade this."""
    plugin = tmp_path / "esc_sql_plugin"
    plugin.mkdir()
    (plugin / "sqli.php").write_text(
        "<?php\n"
        "function cordyceps_esc_sql_handler() {\n"
        "    global $wpdb;\n"
        "    $id = wp_unslash($_GET['id']);\n"
        "    esc_sql($id);\n"
        "    return $wpdb->get_results(\"SELECT * FROM t WHERE id = \" . $id);\n"
        "}\n"
    )
    sqli = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    assert sqli, "expected an SQL Injection finding"
    assert all(f.severity == "CRITICAL" for f in sqli), (
        "esc_sql() must not downgrade: " + ", ".join(f"{f.severity}@{f.line}" for f in sqli)
    )


def test_sink_gate_drops_wp_unslash_without_sql(tmp_path: Path) -> None:
    """The reported 3/3 false positives were all wp_unslash() with no SQL in scope."""
    shutil.copytree(VULN_DIR, tmp_path / "vulnerable_plugin")
    sqli = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    lines = {f.line for f in sqli}
    assert lines == {10}, f"expected only the real handler's source line, got {sorted(lines)}"


def test_auth_context_is_function_scoped(tmp_path: Path) -> None:
    """A nopriv handler elsewhere in the file must not label an unrelated function."""
    plugin = tmp_path / "scoped_plugin"
    plugin.mkdir()
    (plugin / "main.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_cordyceps', 'cordyceps_public_handler');\n"
        "function cordyceps_public_handler() {\n"
        "    include($_GET['tpl']);\n"
        "}\n"
        "function cordyceps_unrelated_include() {\n"
        "    include($_POST['tpl']);\n"
        "}\n"
    )
    by_func = {f.line: f for f in _scan(tmp_path).findings if f.vuln_type == "Local File Inclusion (LFI)"}
    assert 4 in by_func and 7 in by_func, f"expected both include sites, got {sorted(by_func)}"
    assert by_func[4].auth_required == "Unauthenticated"
    assert by_func[7].auth_required != "Unauthenticated"
    assert by_func[7].cvss_estimate < 9.8


def test_autoloader_is_not_an_lfi(tmp_path: Path) -> None:
    """`require $var` with no request source was 92% of LFI output and 2 of 3 top findings."""
    plugin = tmp_path / "autoload_plugin"
    plugin.mkdir()
    (plugin / "main.php").write_text(
        "<?php\n"
        "function cordyceps_autoload($class) {\n"
        "    $file = __DIR__ . '/src/' . str_replace('\\\\', '/', $class) . '.php';\n"
        "    require_once $file;\n"
        "}\n"
    )
    lfi = [f for f in _scan(tmp_path).findings if f.vuln_type == "Local File Inclusion (LFI)"]
    assert lfi == [], f"autoloader must not be LFI, got {[f.line for f in lfi]}"


def test_add_query_arg_needs_an_echo(tmp_path: Path) -> None:
    """Bare add_query_arg() is a WP URL helper, not output. 870 hits/100 plugins, 64% sourceless."""
    plugin = tmp_path / "qa_plugin"
    plugin.mkdir()
    (plugin / "main.php").write_text(
        "<?php\n"
        "function cordyceps_build_url() {\n"
        "    $url = add_query_arg('page', 2);\n"
        "    return $url;\n"
        "}\n"
        "function cordyceps_render() {\n"
        "    echo add_query_arg('page', 2);\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Cross-Site Scripting (XSS)"}
    assert lines == {7}, f"only the echoed call is XSS, got {sorted(lines)}"


def test_apostrophe_in_comment_does_not_eat_the_file() -> None:
    """`// don't` opened a string that never closed, losing 5 of 136 bodies in one real file."""
    text = (
        "<?php\n"
        "function cordyceps_commented() {\n"
        "    // make sure we don't link to ourselves\n"
        "    $x = 1;\n"
        "}\n"
        "function cordyceps_after() {\n"
        "    $y = 2;\n"
        "}\n"
    )
    spans = PatchstackScanner._function_spans(text)
    assert [s[0] for s in spans] == ["cordyceps_commented", "cordyceps_after"]
    assert PatchstackScanner._enclosing_span(spans, 7)[0] == "cordyceps_after"


def test_shortcode_registration_category_is_gone(tmp_path: Path) -> None:
    """`add_shortcode(` matched every shortcode in WordPress: 243 hits/100 plugins, 97% sourceless."""
    assert "Shortcode XSS" not in PatchstackScanner.VULN_PATTERNS


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


def test_guarded_nopriv_handler_is_not_a_finding(tmp_path: Path) -> None:
    """77% of resolvable nopriv callbacks check inside the body. Only the unguarded one counts."""
    plugin = tmp_path / "nopriv_plugin"
    plugin.mkdir()
    (plugin / "main.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_guarded', 'cordyceps_guarded');\n"
        "add_action('wp_ajax_nopriv_open', 'cordyceps_open');\n"
        "add_action('wp_ajax_nopriv_missing', 'cordyceps_not_in_this_file');\n"
        "function cordyceps_guarded() {\n"
        "    check_ajax_referer('cordyceps');\n"
        "}\n"
        "function cordyceps_open() {\n"
        "    update_option('x', 1);\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {3, 4}, f"guarded handler must drop, unresolved must stay, got {sorted(lines)}"


def test_table_name_concat_is_not_sqli(tmp_path: Path) -> None:
    """Hand-checked 37/37 then 15/15 false: this rule only ever matched table/column names."""
    plugin = tmp_path / "concat_plugin"
    plugin.mkdir()
    (plugin / "db.php").write_text(
        "<?php\n"
        "function cordyceps_drop() {\n"
        "    global $wpdb;\n"
        "    $wpdb->query(\"DROP TABLE IF EXISTS \" . $wpdb->prefix . 'x');\n"
        "    $wpdb->query(\"ALTER TABLE `\" . $table . \"` CHANGE `\" . $column->Field . \"`\");\n"
        "}\n"
    )
    sqli = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    assert sqli == [], f"table-name concatenation is not SQLi, got {[f.line for f in sqli]}"


def test_laundered_request_var_still_reaches_sql(tmp_path: Path) -> None:
    """Deleting the concat rule must not lose `$id = wp_unslash($_GET[..]); ... " . $id`.

    The wp_unslash rule plus the sink gate still emits it, anchored at the source line
    instead of the query line. This is the check that the deletion cost no coverage.
    """
    plugin = tmp_path / "laundered_plugin"
    plugin.mkdir()
    (plugin / "db.php").write_text(
        "<?php\n"
        "function cordyceps_lookup() {\n"
        "    global $wpdb;\n"
        "    $id = wp_unslash($_GET['id']);\n"
        "    return $wpdb->get_results(\"SELECT * FROM t WHERE id = \" . $id);\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    assert lines == {4}, f"laundered request var must still be flagged, got {sorted(lines)}"


def test_isset_guard_on_files_is_not_an_upload(tmp_path: Path) -> None:
    """40% of the $_FILES rule's 145 hits were `if ( ! isset( $_FILES[..] ) )` -- the guard."""
    plugin = tmp_path / "upload_plugin"
    plugin.mkdir()
    (plugin / "up.php").write_text(
        "<?php\n"
        "function cordyceps_upload() {\n"
        "    if ( ! isset( $_FILES['file'] ) ) {\n"
        "        return;\n"
        "    }\n"
        "    $file = $_FILES['file'];\n"
        # The scope has to write the upload, or it is not an upload vulnerability at all.
        # `file_put_contents` and not `move_uploaded_file`, which is a rule pattern of its own
        # and would become the one lead this function is allowed to produce.
        "    file_put_contents( '/var/www/u.php', file_get_contents( $file['tmp_name'] ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Arbitrary File Upload"}
    assert lines == {6}, f"only the use, not the guard, is a finding: got {sorted(lines)}"


def test_reading_an_upload_without_writing_it_is_not_an_upload_bug(tmp_path: Path) -> None:
    """All 14 upload findings on the fresh corpus were scopes that never wrote the file."""
    plugin = tmp_path / "csv_plugin"
    plugin.mkdir()
    (plugin / "csv.php").write_text(
        "<?php\n"
        "function cordyceps_import() {\n"
        # A CSV importer: it reads the temp file and never puts it anywhere.
        "    $rows = array_map( 'str_getcsv', file( $_FILES['csv']['tmp_name'] ) );\n"
        "    return count( $rows );\n"
        "}\n"
        "function cordyceps_save() {\n"
        "    $tmp = $_FILES['img']['tmp_name'];\n"
        "    move_uploaded_file( $tmp, ABSPATH . 'wp-content/uploads/' . $_FILES['img']['name'] );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Arbitrary File Upload"}
    assert lines == {8}, f"only the scope that writes the upload is a lead: got {sorted(lines)}"


def test_webhook_that_checks_its_own_secret_is_not_broken_access_control(tmp_path: Path) -> None:
    """7 of 23 BAC findings on the fresh corpus guarded themselves, 4 of them one call out."""
    plugin = tmp_path / "hook_plugin"
    plugin.mkdir()
    (plugin / "hook.php").write_text(
        "<?php\n"
        "class Hooks {\n"
        "    public function register() {\n"
        "        register_rest_route( 'x/v1', '/paid', array(\n"
        "            'methods'             => 'POST',\n"
        "            'callback'            => array( $this, 'handle' ),\n"
        "            'permission_callback' => '__return_true',\n"
        "        ) );\n"
        "        register_rest_route( 'x/v1', '/stats', array(\n"
        "            'methods'             => 'GET',\n"
        "            'callback'            => array( $this, 'stats' ),\n"
        "            'permission_callback' => '__return_true',\n"
        "        ) );\n"
        "    }\n"
        # The check is one hop out, in a helper -- payslate's Stripe webhook exactly.
        "    public function handle( $request ) {\n"
        "        if ( ! $this->verify_signature( $request ) ) {\n"
        "            return new WP_Error( 'bad_sig', 'no' );\n"
        "        }\n"
        "        return rest_ensure_response( array( 'ok' => true ) );\n"
        "    }\n"
        "    private function verify_signature( $request ) {\n"
        "        return hash_equals( get_option( 'x_secret' ), $request->get_header( 'x-sig' ) );\n"
        "    }\n"
        "    public function stats( $request ) {\n"
        "        return rest_ensure_response( get_option( 'x_stats' ) );\n"
        "    }\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {12}, f"only the route with no check anywhere is a lead: got {sorted(lines)}"


def test_comment_lines_are_never_findings(tmp_path: Path) -> None:
    """A `@see \\ZipArchive::extractTo()` docblock was reported CRITICAL. 10/844 sat on comments."""
    plugin = tmp_path / "comment_plugin"
    plugin.mkdir()
    (plugin / "c.php").write_text(
        "<?php\n"
        "/**\n"
        " * @see \\ZipArchive::extractTo()\n"
        " */\n"
        "function cordyceps_doc() {\n"
        "    // move_uploaded_file($a, $b);\n"
        "    # unzip_file($a, $b);\n"
        "    return 1;\n"
        "}\n"
    )
    assert _scan(tmp_path).findings == [], (
        "comments are not code: " + ", ".join(f"{f.vuln_type}@{f.line}" for f in _scan(tmp_path).findings)
    )


def test_curl_exec_alone_is_not_ssrf(tmp_path: Path) -> None:
    """`curl_exec(` said "verify the URL" and nothing did: 43 hits/100 plugins, 86% sourceless."""
    plugin = tmp_path / "curl_plugin"
    plugin.mkdir()
    (plugin / "http.php").write_text(
        "<?php\n"
        "function cordyceps_fetch() {\n"
        "    $ch = curl_init('https://example.test/');\n"
        "    return curl_exec($ch);\n"
        "}\n"
    )
    ssrf = [f for f in _scan(tmp_path).findings if "SSRF" in f.vuln_type]
    assert ssrf == [], f"bare curl_exec must not be SSRF, got {[f.line for f in ssrf]}"


def test_printf_template_needs_a_request_value(tmp_path: Path) -> None:
    """The bare form matched every templated HTML printf: 77 hits/100 plugins, 6 with a source."""
    plugin = tmp_path / "printf_plugin"
    plugin.mkdir()
    (plugin / "render.php").write_text(
        "<?php\n"
        "function cordyceps_render() {\n"
        "    printf('<a href=\"%s\">', esc_url($safe));\n"
        "    printf('<a href=\"%s\">', $_GET['u']);\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Cross-Site Scripting (XSS)"}
    assert lines == {4}, f"only the request-fed printf is XSS, got {sorted(lines)}"


def test_strict_comparison_is_not_type_juggling(tmp_path: Path) -> None:
    """`==` matched the tail of `===`, so the rule flagged the fix it recommends. 157/157 hits."""
    plugin = tmp_path / "juggle_plugin"
    plugin.mkdir()
    (plugin / "cmp.php").write_text(
        "<?php\n"
        "function cordyceps_cmp() {\n"
        "    if ( 'revoke' === $_GET['action'] ) { return 1; }\n"
        "    if ( 'revoke' !== $_GET['action'] ) { return 2; }\n"
        "    if ( 'revoke' == $_GET['action'] ) { return 3; }\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Type Juggling"}
    assert lines == {5}, f"only the loose comparison is a finding, got {sorted(lines)}"


def test_isset_check_is_not_a_use(tmp_path: Path) -> None:
    """63/121 `echo ... $_GET` findings had the superglobal only inside isset()."""
    plugin = tmp_path / "isset_plugin"
    plugin.mkdir()
    (plugin / "v.php").write_text(
        "<?php\n"
        "function cordyceps_view() {\n"
        "    echo isset( $_GET['tab'] ) ? ' selected' : '';\n"
        "    echo $_GET['tab'];\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Cross-Site Scripting (XSS)"}
    assert lines == {4}, f"the isset() test is not an echo of user input, got {sorted(lines)}"


def test_escaped_output_is_not_xss(tmp_path: Path) -> None:
    """42/181 XSS findings over 100 plugins already escaped the value on the matched line."""
    plugin = tmp_path / "esc_plugin"
    plugin.mkdir()
    (plugin / "v.php").write_text(
        "<?php\n"
        "function cordyceps_render() {\n"
        "    echo esc_attr( $_GET['tab'] );\n"
        "    echo intval( $_GET['id'] );\n"
        "    echo esc_html( $_GET['a'] ) . $_GET['b'];\n"
        "    echo $_GET['raw'];\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Cross-Site Scripting (XSS)"}
    # 3 and 4 are escaped, so the first surviving line is 5 -- which mixes an escaped and a
    # bare value, proving one bare occurrence keeps the finding. 6 is the same function and
    # collapses into 5 by the one-lead-per-function rule.
    assert lines == {5}, f"only unescaped output is XSS, got {sorted(lines)}"


def test_output_escaper_does_not_clear_sql_injection(tmp_path: Path) -> None:
    """esc_attr() is not a SQL escape. Only the numeric cast may suppress here."""
    plugin = tmp_path / "escsql_plugin"
    plugin.mkdir()
    (plugin / "v.php").write_text(
        "<?php\n"
        "function cordyceps_q() {\n"
        "    global $wpdb;\n"
        "    $a = esc_attr( wp_unslash( $_GET['a'] ) );\n"
        "    $b = absint( wp_unslash( $_GET['b'] ) );\n"
        "    return $wpdb->get_results( \"SELECT * FROM t WHERE a = '$a' AND b = $b\" );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    assert lines == {4}, f"esc_attr must not clear a SQL finding, got {sorted(lines)}"


def test_one_handler_many_hooks_is_one_finding(tmp_path: Path) -> None:
    """echo-knowledge-base bound one handler to 52 hook names: 52 of 206 BAC findings."""
    plugin = tmp_path / "dedup_plugin"
    plugin.mkdir()
    (plugin / "main.php").write_text(
        "<?php\n"
        "add_action( 'wp_ajax_nopriv_a', array( 'Utils', 'shared' ) );\n"
        "add_action( 'wp_ajax_nopriv_b', array( 'Utils', 'shared' ) );\n"
        "add_action( 'wp_ajax_nopriv_c', 'other' );\n"
        "function shared() { echo 1; }\n"
        "function other() { echo 2; }\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {2, 4}, f"the repeat registration must collapse, got {sorted(lines)}"


def test_rest_route_whose_handler_checks_caps_is_not_a_finding(tmp_path: Path) -> None:
    """11 of 51 __return_true routes guard inside the callback instead of permission_callback."""
    plugin = tmp_path / "rest_plugin"
    plugin.mkdir()
    (plugin / "api.php").write_text(
        "<?php\n"
        "function cordyceps_routes() {\n"
        "    register_rest_route( 'x/v1', '/safe', array(\n"
        "        'callback'            => 'cordyceps_safe',\n"
        "        'permission_callback' => '__return_true',\n"
        "    ) );\n"
        "    register_rest_route( 'x/v1', '/open', array(\n"
        "        'callback'            => 'cordyceps_open',\n"
        "        'permission_callback' => '__return_true',\n"
        "    ) );\n"
        "}\n"
        "function cordyceps_safe() { if ( ! current_user_can( 'manage_options' ) ) { return; } }\n"
        "function cordyceps_open() { return get_option( 'x' ); }\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {9}, f"only the unguarded route is a finding, got {sorted(lines)}"


def test_laundered_request_var_reaches_unlink(tmp_path: Path) -> None:
    """`unlink($_GET[..])` matched 0 lines against 305 sink lines. Real code launders first."""
    plugin = tmp_path / "fdel_plugin"
    plugin.mkdir()
    (plugin / "d.php").write_text(
        "<?php\n"
        "function cordyceps_remove() {\n"
        "    $f = sanitize_text_field( wp_unslash( $_POST['file'] ) );\n"
        "    unlink( WP_CONTENT_DIR . '/' . $f );\n"
        "}\n"
        "function cordyceps_no_sink() {\n"
        "    return sanitize_text_field( wp_unslash( $_POST['name'] ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings
             if f.vuln_type == "Arbitrary File Deletion"}
    assert lines == {3}, f"the sink gate must keep 3 and drop 7, got {sorted(lines)}"


def test_laundered_request_var_reaches_file_read(tmp_path: Path) -> None:
    """Same hole for reads: 0 raw matches against 557 sink lines over 26 hunt-flagged plugins."""
    plugin = tmp_path / "fread_plugin"
    plugin.mkdir()
    (plugin / "r.php").write_text(
        "<?php\n"
        "function cordyceps_dump() {\n"
        "    $p = wp_unslash( $_GET['path'] );\n"
        "    return file_get_contents( ABSPATH . $p );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Arbitrary File Read"}
    assert lines == {3}, f"laundered path must reach the read sink, got {sorted(lines)}"


def test_nonce_check_is_not_a_finding(tmp_path: Path) -> None:
    """The first FP ever reported: a nonce check labelled CRITICAL SQL Injection."""
    plugin = tmp_path / "nonce_plugin"
    plugin.mkdir()
    (plugin / "n.php").write_text(
        "<?php\n"
        "function cordyceps_save() {\n"
        "    if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['n'] ) ), 'a' ) ) {\n"
        "        return;\n"
        "    }\n"
        "    global $wpdb;\n"
        "    $wpdb->query( 'SELECT 1' );\n"
        "}\n"
        "function cordyceps_bad() {\n"
        "    global $wpdb;\n"
        "    $wpdb->query( wp_unslash( $_POST['q'] ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    # 3 is the plugin's own protection; 11 is the bug. The guard must not cost recall.
    assert lines == {11}, f"nonce line must not be a finding, got {sorted(lines)}"


def test_one_function_is_one_lead(tmp_path: Path) -> None:
    """houzez-property-feed's save_import_settings produced 37 findings for one function."""
    plugin = tmp_path / "dedup_plugin"
    plugin.mkdir()
    (plugin / "s.php").write_text(
        "<?php\n"
        "function cordyceps_save_settings() {\n"
        "    global $wpdb;\n"
        "    $a = wp_unslash( $_POST['a'] );\n"
        "    $b = wp_unslash( $_POST['b'] );\n"
        "    $c = wp_unslash( $_POST['c'] );\n"
        "    $wpdb->query( \"SELECT $a $b $c\" );\n"
        "}\n"
        "function cordyceps_other() {\n"
        "    global $wpdb;\n"
        "    $wpdb->query( wp_unslash( $_POST['d'] ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    # One per function: the first line of each, not every request read.
    assert lines == {4, 11}, f"each function is one lead, got {sorted(lines)}"


def test_boilerplate_loader_handler_is_resolved_across_files(tmp_path: Path) -> None:
    """WPPB splits loader and handler across files: 0 of 27 resolve same-file, 26 guard plugin-wide."""
    plugin = tmp_path / "wppb_plugin"
    (plugin / "includes").mkdir(parents=True)
    (plugin / "public").mkdir()
    (plugin / "includes" / "class-loader.php").write_text(
        "<?php\n"
        "function cordyceps_define_hooks() {\n"
        "    $this->loader->add_action( 'wp_ajax_nopriv_safe', $pub, 'handle_safe' );\n"
        "    $this->loader->add_action( 'wp_ajax_nopriv_open', $pub, 'handle_open' );\n"
        "}\n"
    )
    (plugin / "public" / "class-public.php").write_text(
        "<?php\n"
        "function handle_safe() {\n"
        "    if ( ! current_user_can( 'manage_options' ) ) { return; }\n"
        "}\n"
        "function handle_open() {\n"
        "    return 1;\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    # Line 3's handler guards in another file; line 4's does not.
    assert lines == {4}, f"only the unguarded loader line is a finding, got {sorted(lines)}"


def test_unresolvable_handler_still_emits(tmp_path: Path) -> None:
    """Absence from the index is not evidence. Fallback never suppresses."""
    plugin = tmp_path / "unres_plugin"
    plugin.mkdir()
    (plugin / "main.php").write_text(
        "<?php\n"
        "add_action( 'wp_ajax_nopriv_x', array( $obj, 'nowhere_defined' ) );\n"
        "function cordyceps_guarded_decoy() {\n"
        "    if ( ! current_user_can( 'manage_options' ) ) { return; }\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {2}, f"unresolvable handler must still emit, got {sorted(lines)}"


def test_localize_script_nonce_rule_is_gone() -> None:
    """52 raw hits over 18/100 plugins for the documented way to hand a nonce to JS."""
    pats = [p for p, _ in PatchstackScanner.VULN_PATTERNS["Broken Access Control"]["patterns"]]
    assert not any("wp_localize_script" in p for p in pats)


def test_ambiguous_handler_name_does_not_suppress(tmp_path: Path) -> None:
    """The index is keyed by name, not class: 141 of 4,348 duplicated names disagree on guarding."""
    plugin = tmp_path / "ambig_plugin"
    (plugin / "inc").mkdir(parents=True)
    # The registration lives in its own file so only the plugin-wide index can resolve it.
    (plugin / "inc" / "hooks.php").write_text(
        "<?php\n"
        "add_action( 'wp_ajax_nopriv_x', array( $obj, 'render' ) );\n"
    )
    (plugin / "inc" / "a.php").write_text(
        "<?php\n"
        "function render() {\n"
        "    if ( ! current_user_can( 'manage_options' ) ) { return; }\n"
        "}\n"
    )
    (plugin / "inc" / "b.php").write_text(
        "<?php\n"
        "function render() {\n"
        "    return 1;\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    # One `render()` guards and one does not, so the name proves nothing and the finding stands.
    assert lines == {2}, f"an ambiguous name must not suppress, got {sorted(lines)}"


def test_closure_body_is_a_scope(tmp_path: Path) -> None:
    """`add_action('wp_ajax_x', function(){...})` had no span, so scope fell back to the file."""
    plugin = tmp_path / "closure_plugin"
    plugin.mkdir()
    (plugin / "s.php").write_text(
        "<?php\n"
        "add_action( 'wp_ajax_safe', function() {\n"
        "    if ( ! current_user_can( 'manage_options' ) ) { wp_die(); }\n"
        "    $a = wp_unslash( $_POST['a'] );\n"
        "    $b = wp_unslash( $_POST['b'] );\n"
        "    $wpdb->query( \"SELECT $a $b\" );\n"
        "} );\n"
        "function cordyceps_no_sql() {\n"
        "    $c = wp_unslash( $_POST['c'] );\n"
        "}\n"
    )
    sqli = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    # 4 and 5 are one closure, so one lead. 9 has no SQL sink in its own span -- before the
    # closure resolved, the whole file was its scope and the query on line 6 kept it alive.
    assert {f.line for f in sqli} == {4}, f"one closure is one scope, got {sorted(f.line for f in sqli)}"
    # The capability check is inside the closure, so the finding must not read as unauthenticated.
    assert "Unauthenticated" not in sqli[0].auth_required, sqli[0].auth_required


def test_wpdb_escaping_api_is_not_a_sql_sink(tmp_path: Path) -> None:
    """$wpdb->insert/update/delete/replace escape their own values: 24 of 80 SQLi lived on this."""
    plugin = tmp_path / "wpdb_api_plugin"
    plugin.mkdir()
    (plugin / "s.php").write_text(
        "<?php\n"
        "function cordyceps_add_row() {\n"
        "    global $wpdb;\n"
        "    $label = wp_unslash( $_POST['label'] );\n"
        "    $wpdb->insert( $wpdb->prefix . 't', array( 'label' => $label ) );\n"
        "}\n"
        "function cordyceps_raw_query() {\n"
        "    global $wpdb;\n"
        "    $wpdb->query( \"SELECT * FROM t WHERE x = \" . wp_unslash( $_POST['x'] ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    assert lines == {9}, f"only the raw query is a sink, got {sorted(lines)}"


def test_escaped_query_arg_is_not_xss(tmp_path: Path) -> None:
    """add_query_arg() names no superglobal, so 28 of 28 `echo esc_url(add_query_arg())` fired."""
    plugin = tmp_path / "qarg_plugin"
    plugin.mkdir()
    (plugin / "s.php").write_text(
        "<?php\n"
        "function cordyceps_links() {\n"
        "    echo esc_url( add_query_arg( 'page', 2 ) );\n"
        "}\n"
        "function cordyceps_bare_link() {\n"
        "    echo add_query_arg( 'page', 2 );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Cross-Site Scripting (XSS)"}
    assert lines == {6}, f"only the unescaped URL is XSS, got {sorted(lines)}"


def test_value_must_reach_the_sink(tmp_path: Path) -> None:
    """The sink gate proved a sink existed in the span, never that the value got there."""
    plugin = tmp_path / "reach_plugin"
    plugin.mkdir()
    (plugin / "s.php").write_text(
        "<?php\n"
        "function cordyceps_unrelated() {\n"
        "    global $wpdb;\n"
        "    $phone = wp_unslash( $_POST['phone'] );\n"
        "    $wpdb->update( 't', array( 'phone' => $phone ), array( 'id' => 1 ) );\n"
        "    $wpdb->query( \"SELECT id FROM t WHERE k = 1\" );\n"
        "}\n"
        "function cordyceps_interpolated() {\n"
        "    global $wpdb;\n"
        "    $id = wp_unslash( $_POST['id'] );\n"
        "    $sql = \"SELECT *\n"
        "        FROM t WHERE id = $id\";\n"
        "    $wpdb->query( $sql );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    # 4 never reaches the raw query -- it only feeds $wpdb->update(), which escapes. 10 does,
    # through a $sql whose SELECT opens on one line and interpolates $id on the next.
    assert lines == {10}, f"only the value that reaches a sink is a lead, got {sorted(lines)}"


def test_array_element_use_site_is_the_statement(tmp_path: Path) -> None:
    """12 survivors were one array element inside a redirect, with no assignment on the line."""
    plugin = tmp_path / "stmt_plugin"
    plugin.mkdir()
    (plugin / "s.php").write_text(
        "<?php\n"
        "function cordyceps_redirect_back() {\n"
        "    global $wpdb;\n"
        "    $wpdb->query( \"SELECT 1 FROM t\" );\n"
        "    wp_safe_redirect( add_query_arg( array(\n"
        "        'msg' => sanitize_key( wp_unslash( $_GET['msg'] ) ),\n"
        "    ), admin_url() ) );\n"
        "}\n"
    )
    findings = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    # The unrelated query on line 4 satisfies the span-level sink gate; the statement the
    # value actually lives in is a redirect, so it is not a lead.
    assert findings == [], f"a redirect argument is not a SQL lead, got {findings}"


def test_prepare_argument_is_escaped_but_interpolation_is_not(tmp_path: Path) -> None:
    """11 of 14 surviving SQL leads on the fresh corpus were the safe `prepare(…, $x)` form."""
    plugin = tmp_path / "prep_plugin"
    plugin.mkdir()
    (plugin / "p.php").write_text(
        "<?php\n"
        "function cordyceps_safe() {\n"
        "    global $wpdb;\n"
        "    $slug = sanitize_text_field( wp_unslash( $_GET['slug'] ) );\n"
        "    return $wpdb->get_var( $wpdb->prepare(\n"
        "        \"SELECT name FROM {$wpdb->prefix}items WHERE slug = %s\",\n"
        "        $slug\n"
        "    ) );\n"
        "}\n"
        "function cordyceps_unsafe() {\n"
        "    global $wpdb;\n"
        "    $id = wp_unslash( $_GET['id'] );\n"
        "    $sql = \"SELECT name FROM {$wpdb->prefix}items WHERE id = $id\";\n"
        "    return $wpdb->get_var( $sql );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"}
    assert lines == {12}, f"only the interpolated one is a lead: got {sorted(lines)}"


def test_placeholder_list_and_prepared_fragment_are_not_tainted(tmp_path: Path) -> None:
    """`IN (%d,%d)` built by array_fill, and a WHERE built by prepare, are the documented idiom."""
    plugin = tmp_path / "ph_plugin"
    plugin.mkdir()
    (plugin / "ph.php").write_text(
        "<?php\n"
        "function cordyceps_in_clause() {\n"
        "    global $wpdb;\n"
        "    $ids = array_map( 'intval', wp_unslash( $_POST['ids'] ) );\n"
        "    $ph = implode( ',', array_fill( 0, count( $ids ), '%d' ) );\n"
        "    $where = $wpdb->prepare( ' AND status = %s', sanitize_key( $_POST['status'] ) );\n"
        "    return $wpdb->get_col( $wpdb->prepare(\n"
        "        \"SELECT id FROM {$wpdb->prefix}t WHERE id IN ($ph) $where\",\n"
        "        ...$ids\n"
        "    ) );\n"
        "}\n"
    )
    findings = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    assert findings == [], f"placeholders and prepared fragments carry no value, got {findings}"


def test_html_select_tag_is_not_a_sql_statement(tmp_path: Path) -> None:
    """`<select name="from">` supplies both halves of `SELECT … FROM` under IGNORECASE."""
    plugin = tmp_path / "html_plugin"
    plugin.mkdir()
    (plugin / "h.php").write_text(
        "<?php\n"
        "function cordyceps_form() {\n"
        "    $from = sanitize_key( wp_unslash( $_GET['from'] ) );\n"
        "    echo '<select name=\"from\">';\n"
        "    echo '<option>' . esc_html( $from ) . '</option>';\n"
        "    echo '</select>';\n"
        "}\n"
    )
    findings = [f for f in _scan(tmp_path).findings if f.vuln_type == "SQL Injection"]
    assert findings == [], f"markup is not a SQL sink, got {findings}"


def test_basename_defeats_traversal_but_a_raw_name_does_not(tmp_path: Path) -> None:
    """2 of 4 file-read findings were `basename( sanitize_file_name( wp_unslash( $_GET ) ) )`."""
    plugin = tmp_path / "log_plugin"
    plugin.mkdir()
    (plugin / "l.php").write_text(
        "<?php\n"
        "function cordyceps_show_log() {\n"
        "    $name = basename( sanitize_file_name( wp_unslash( $_GET['log_file'] ) ) );\n"
        "    echo file_get_contents( WP_CONTENT_DIR . '/logs/' . $name );\n"
        "}\n"
        "function cordyceps_show_any() {\n"
        "    echo file_get_contents( WP_CONTENT_DIR . '/logs/' . wp_unslash( $_GET['f'] ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Arbitrary File Read"}
    assert lines == {7}, f"only the un-basenamed path is a lead: got {sorted(lines)}"


def test_sanitize_key_output_cannot_carry_a_tag(tmp_path: Path) -> None:
    """`sanitize_key()` leaves only `[a-z0-9_-]`, so its output is safe in any HTML context."""
    plugin = tmp_path / "key_plugin"
    plugin.mkdir()
    (plugin / "k.php").write_text(
        "<?php\n"
        "function cordyceps_render() {\n"
        "    echo '<div class=' . sanitize_key( wp_unslash( $_GET['tab'] ) ) . '>';\n"
        "    echo '<div class=' . sanitize_text_field( wp_unslash( $_GET['other'] ) ) . '>';\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if "Cross-Site" in f.vuln_type}
    # sanitize_text_field strips tags but keeps quotes: still XSS in an unquoted attribute.
    assert lines == {4}, f"only the quote-preserving sanitizer is a lead: got {sorted(lines)}"


def test_a_403_and_a_nonce_dispenser_are_not_broken_access_control(tmp_path: Path) -> None:
    """7 of 16 BAC findings: 3 handlers answer 401/403, 4 hand out a nonce and nothing else."""
    plugin = tmp_path / "route_plugin"
    plugin.mkdir()
    (plugin / "r.php").write_text(
        "<?php\n"
        "function cordyceps_routes() {\n"
        "    register_rest_route( 'x/v1', '/hook', array(\n"
        "        'callback'            => 'cordyceps_hook',\n"
        "        'permission_callback' => '__return_true',\n"
        "    ) );\n"
        "    register_rest_route( 'x/v1', '/nonce', array(\n"
        "        'callback'            => 'cordyceps_nonce',\n"
        "        'permission_callback' => '__return_true',\n"
        "    ) );\n"
        "    register_rest_route( 'x/v1', '/wipe', array(\n"
        "        'callback'            => 'cordyceps_wipe',\n"
        "        'permission_callback' => '__return_true',\n"
        "    ) );\n"
        "}\n"
        "function cordyceps_hook( $request ) {\n"
        "    if ( $request->get_header( 'x-secret' ) !== get_option( 'my_secret' ) ) {\n"
        "        return new WP_REST_Response( array( 'ok' => false ), 403 );\n"
        "    }\n"
        "    return new WP_REST_Response( array( 'ok' => true ), 200 );\n"
        "}\n"
        "function cordyceps_nonce() {\n"
        "    return wp_create_nonce( 'my_action' );\n"
        "}\n"
        "function cordyceps_wipe( $request ) {\n"
        "    delete_option( $request->get_param( 'key' ) );\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {13}, f"only the route that authorises nothing is a lead: got {sorted(lines)}"


def test_a_concatenated_hook_name_still_resolves_its_handler(tmp_path: Path) -> None:
    """`'wp_ajax_nopriv_' . self::ACTION` hid the callback, so a guarded handler still emitted."""
    plugin = tmp_path / "ajax_plugin"
    plugin.mkdir()
    (plugin / "a.php").write_text(
        "<?php\n"
        "class Cordyceps_Sub {\n"
        "    const ACTION = 'cordyceps_subscribe';\n"
        "    public function register() {\n"
        "        add_action( 'wp_ajax_nopriv_' . self::ACTION, array( $this, 'handle' ) );\n"
        "        add_action( 'wp_ajax_nopriv_' . self::ACTION . '_open', array( $this, 'open' ) );\n"
        "    }\n"
        "    public function handle() {\n"
        "        check_ajax_referer( self::ACTION, 'nonce' );\n"
        "        update_option( 'sub', sanitize_text_field( wp_unslash( $_POST['email'] ) ) );\n"
        "    }\n"
        "    public function open() {\n"
        "        update_option( 'sub', sanitize_text_field( wp_unslash( $_POST['email'] ) ) );\n"
        "    }\n"
        "}\n"
    )
    lines = {f.line for f in _scan(tmp_path).findings if f.vuln_type == "Broken Access Control"}
    assert lines == {6}, f"only the unguarded handler is a lead: got {sorted(lines)}"
