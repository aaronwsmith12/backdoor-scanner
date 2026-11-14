<?php
/**
 * Plugin Name: Backdoor Scanner
 * Description: Flags common WordPress backdoors.
 * Version: 0.1.0
 * Author: Aaron Smith
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

add_action( 'admin_menu', 'bs_add_admin_page' );

function bs_add_admin_page() {
    add_management_page(
        'Backdoor Scanner',   // Text in the browser tab
        'Backdoor Scanner',   // Text in the Tools menu
        'manage_options',     // Only admins can see it
        'backdoor-scanner',   // The page slug in the URL
        'bs_render_page'      // The function that prints the page
    );
}

function bs_render_page() {
    $admins = get_users( array( 'role' => 'administrator' ) );

    echo '<div class="wrap">';
    echo '<h1>Backdoor Scanner</h1>';
    echo '<h2>Admin users</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr><th>Username</th><th>Email</th><th>Registered</th></tr></thead>';
    echo '<tbody>';

    foreach ( $admins as $admin ) {
        echo '<tr>';
        echo '<td>' . esc_html( $admin->user_login ) . '</td>';
        echo '<td>' . esc_html( $admin->user_email ) . '</td>';
        echo '<td>' . esc_html( $admin->user_registered ) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}