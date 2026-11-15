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
    bs_render_cron_section();
    echo '</div>';
}

function bs_render_cron_section() {
    $crons = _get_cron_array();
    if ( ! $crons ) {
        $crons = array();
    }

    echo '<h2>Scheduled tasks (cron)</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr><th>Hook</th><th>Next run</th><th>Repeats</th><th>Runs</th></tr></thead>';
    echo '<tbody>';

    foreach ( $crons as $timestamp => $hooks ) {
        foreach ( $hooks as $hook => $events ) {
            foreach ( $events as $event ) {
                $repeats = $event['schedule'] ? $event['schedule'] : 'Once';

                echo '<tr>';
                echo '<td>' . esc_html( $hook ) . '</td>';
                echo '<td>' . esc_html( wp_date( 'Y-m-d H:i', $timestamp ) ) . '</td>';
                echo '<td>' . esc_html( $repeats ) . '</td>';

                $runs = '<em>Nothing attached</em>';
                $callbacks = bs_get_hook_callbacks( $hook );
                if ( $callbacks ) {
                    $runs = '';
                    foreach ( $callbacks as $cb ) {
                        $runs .= esc_html( $cb['name'] ) . '<br><code>' . esc_html( $cb['file'] ) . '</code><br>';
                    }
                }
                echo '<td>' . $runs . '</td>';

                echo '</tr>';
            }
        }
    }

    echo '</tbody></table>';
}

function bs_get_hook_callbacks( $hook ) {
    global $wp_filter;

    $found = array();

    if ( empty( $wp_filter[ $hook ] ) ) {
        return $found;
    }

    foreach ( $wp_filter[ $hook ]->callbacks as $priority => $callbacks ) {
        foreach ( $callbacks as $callback ) {
            $function = $callback['function'];

            try {
                if ( is_array( $function ) ) {
                    $reflection = new ReflectionMethod( $function[0], $function[1] );
                    $class      = is_object( $function[0] ) ? get_class( $function[0] ) : $function[0];
                    $name       = $class . '::' . $function[1];
                } else {
                    $reflection = new ReflectionFunction( $function );
                    $name       = is_string( $function ) ? $function : 'Anonymous function';
                }
                $file = str_replace( ABSPATH, '', $reflection->getFileName() );
            } catch ( ReflectionException $e ) {
                $name = 'Unknown';
                $file = 'Unknown';
            }

            $found[] = array(
                'name' => $name,
                'file' => $file,
            );
        }
    }

    return $found;
}