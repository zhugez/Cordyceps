<?php
/*
Plugin Name: Cordyceps Test - Safe Plugin Fixture
Description: Uses prepared statements and proper escaping. Should not produce
CRITICAL findings.
*/
function cordyceps_safe_handler() {
    global $wpdb;
    $id = absint($_GET['id'] ?? 0);
    $rows = $wpdb->get_results(
        $wpdb->prepare("SELECT * FROM {$wpdb->prefix}things WHERE id = %d", $id)
    );
    $name = isset($_GET['name']) ? sanitize_text_field(wp_unslash($_GET['name'])) : '';
    echo esc_html($name);
    return $rows;
}
add_action('admin_init', 'cordyceps_safe_handler');
