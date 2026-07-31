<?php
/*
Plugin Name: Cordyceps Test - SQL Injection Fixture
Description: Intentionally vulnerable code used by the test suite.
*/

// CRITICAL: direct user input concatenated into a $wpdb query without prepare().
function cordyceps_sqli_handler() {
    global $wpdb;
    $id = wp_unslash($_GET['id']);
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}things WHERE id = " . $id);
    echo $_GET['name']; // also reflected XSS for the XSS coverage test
    return $rows;
}
add_action('init', 'cordyceps_sqli_handler');

// NOT a vulnerability: wp_unslash() with no SQL sink anywhere in the function. The
// scanner used to call this CRITICAL SQL Injection; the sink gate must drop it.
function cordyceps_wp_unslash_noise() {
    $value = wp_unslash($_GET['x']);
    return $value;
}
