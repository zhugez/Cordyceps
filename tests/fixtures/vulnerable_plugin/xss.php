<?php
/*
Plugin Name: Cordyceps Test - Reflected XSS Fixture
Description: $_GET echoed without escaping.
*/
function cordyceps_xss_handler() {
    echo $_GET['msg'];
}
add_action('admin_notices', 'cordyceps_xss_handler');
