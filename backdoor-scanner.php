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
    bs_render_file_section();
    bs_render_core_section();
    bs_render_plugin_section();
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
                $file = bs_relative_path( $reflection->getFileName() );
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

function bs_render_file_section() {
    $uploads = wp_upload_dir();

    $results = array_merge(
        bs_scan_files( $uploads['basedir'], true ),  // true = flag every PHP file in uploads
        bs_scan_files( get_theme_root(), false ),
        bs_scan_files( WPMU_PLUGIN_DIR, false )
    );

    echo '<h2>Suspicious code</h2>';
    echo '<p>Checks uploads, themes and must-use plugins. Any PHP file in uploads is flagged, since uploads should only hold media.</p>';

    if ( ! $results ) {
        echo '<p>Nothing found.</p>';
        return;
    }

    echo '<table class="widefat striped">';
    echo '<thead><tr><th>File</th><th>Line</th><th>Found</th><th>Code</th></tr></thead>';
    echo '<tbody>';

    foreach ( $results as $row ) {
        echo '<tr>';
        echo '<td><code>' . esc_html( $row['file'] ) . '</code></td>';
        echo '<td>' . esc_html( $row['line'] ) . '</td>';
        echo '<td>' . esc_html( $row['match'] ) . '</td>';
        echo '<td><code>' . esc_html( $row['code'] ) . '</code></td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
}

function bs_scan_files( $dir, $flag_all_php ) {
    $found = array();

    if ( ! is_dir( $dir ) ) {
        return $found;
    }

    // Function names attackers use to hide or run code. \b stops "filesystem(" matching "system(".
    $pattern    = '/\b(eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|system|passthru|exec|popen|proc_open)\s*\(/i';
    $extensions = array( 'php', 'phtml', 'php5', 'php7', 'inc' );

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
    );

    foreach ( $files as $file ) {
        if ( ! in_array( strtolower( $file->getExtension() ), $extensions, true ) ) {
            continue;
        }
        if ( $file->getSize() > 2 * MB_IN_BYTES ) {
            continue;
        }

        $lines = file( $file->getPathname() );
        if ( false === $lines ) {
            continue;
        }

        $path = bs_relative_path( $file->getPathname() );
        $hits = 0;

        foreach ( $lines as $i => $line ) {
            if ( preg_match_all( $pattern, $line, $m ) ) {
                $hits++;
                $found[] = array(
                    'file'  => $path,
                    'line'  => $i + 1,
                    'match' => implode( '(), ', array_unique( $m[1] ) ) . '()',
                    'code'  => substr( trim( $line ), 0, 120 ),  // Malware is often one huge line, so cut it short
                );
            }
        }

        if ( $flag_all_php && ! $hits ) {
            $found[] = array(
                'file'  => $path,
                'line'  => '-',
                'match' => 'PHP file in uploads',
                'code'  => '',
            );
        }
    }

    return $found;
}

function bs_render_core_section() {
    global $wp_version;

    // get_core_checksums() lives in an admin file that isn't always loaded.
    require_once ABSPATH . 'wp-admin/includes/update.php';

    $checksums = get_core_checksums( $wp_version, get_locale() );
    if ( ! $checksums && 'en_US' !== get_locale() ) {
        $checksums = get_core_checksums( $wp_version, 'en_US' );
    }

    echo '<h2>Core files</h2>';

    if ( ! $checksums ) {
        echo '<p>Could not get the checksum list from WordPress.org for version ' . esc_html( $wp_version ) . '.</p>';
        return;
    }

    echo '<p>Compares WordPress core files with the official list for version ' . esc_html( $wp_version ) . '.</p>';

    $results = array();

    // 1. Changed or missing core files.
    foreach ( $checksums as $file => $md5 ) {
        if ( 0 === strpos( $file, 'wp-content/' ) ) {
            continue; // Themes and plugins are meant to change.
        }

        $path = ABSPATH . $file;

        if ( ! file_exists( $path ) ) {
            $results[] = array( 'file' => $file, 'problem' => 'Missing' );
        } elseif ( md5_file( $path ) !== $md5 ) {
            $results[] = array( 'file' => $file, 'problem' => 'Changed' );
        }
    }

    // 2. Extra files hiding in wp-admin and wp-includes.
    foreach ( array( 'wp-admin', 'wp-includes' ) as $folder ) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( ABSPATH . $folder, FilesystemIterator::SKIP_DOTS )
        );

        foreach ( $files as $file ) {
            $relative = bs_relative_path( $file->getPathname() );
            if ( ! isset( $checksums[ $relative ] ) ) {
                $results[] = array( 'file' => $relative, 'problem' => 'Not part of WordPress' );
            }
        }
    }

    // 3. Extra PHP files in the root folder. wp-config.php is the only one that should be there.
    foreach ( glob( ABSPATH . '*.php' ) as $path ) {
        $relative = basename( $path );
        if ( 'wp-config.php' !== $relative && ! isset( $checksums[ $relative ] ) ) {
            $results[] = array( 'file' => $relative, 'problem' => 'Not part of WordPress' );
        }
    }

    if ( ! $results ) {
        echo '<p>All core files match.</p>';
        return;
    }

    echo '<table class="widefat striped">';
    echo '<thead><tr><th>File</th><th>Problem</th></tr></thead>';
    echo '<tbody>';

    foreach ( $results as $row ) {
        echo '<tr>';
        echo '<td><code>' . esc_html( $row['file'] ) . '</code></td>';
        echo '<td>' . esc_html( $row['problem'] ) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
}

// Turns /wordpress/wp-includes/x.php into wp-includes/x.php.
// Only strips ABSPATH from the start. str_replace would also cut it out of the middle of a path.
function bs_relative_path( $path ) {
    if ( 0 === strpos( $path, ABSPATH ) ) {
        return substr( $path, strlen( ABSPATH ) );
    }
    return $path;
}

function bs_render_plugin_section() {
    require_once ABSPATH . 'wp-admin/includes/plugin.php';

    echo '<h2>Plugins</h2>';
    echo '<p>Compares each plugin with its official file list on WordPress.org. Plugins that are not on WordPress.org are checked for suspicious code instead.</p>';

    $own     = dirname( plugin_basename( __FILE__ ) );
    $results = array();

    foreach ( get_plugins() as $plugin_file => $plugin ) {
        $slug = dirname( $plugin_file );

        // Single-file plugins like hello.php have no folder to check. Skip this scanner too.
        if ( '.' === $slug || $own === $slug ) {
            continue;
        }

        $dir      = WP_PLUGIN_DIR . '/' . $slug;
        $url      = 'https://downloads.wordpress.org/plugin-checksums/' . $slug . '/' . $plugin['Version'] . '.json';
        $response = wp_remote_get( $url );

        if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
            // Not on WordPress.org (or that version isn't), so fall back to the pattern scan.
            foreach ( bs_scan_files( $dir, false ) as $row ) {
                $results[] = array( 'file' => $row['file'], 'problem' => 'Suspicious code: ' . $row['match'] );
            }
            continue;
        }

        $data  = json_decode( wp_remote_retrieve_body( $response ), true );
        $files = isset( $data['files'] ) ? $data['files'] : array();

        // Changed or missing files.
        foreach ( $files as $file => $hashes ) {
            $path = $dir . '/' . $file;
            if ( ! file_exists( $path ) ) {
                $results[] = array( 'file' => bs_relative_path( $path ), 'problem' => 'Missing' );
            } elseif ( ! in_array( md5_file( $path ), (array) $hashes['md5'], true ) ) {
                $results[] = array( 'file' => bs_relative_path( $path ), 'problem' => 'Changed' );
            }
        }

        // Extra PHP files that aren't in the official list.
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS )
        );
        foreach ( $iterator as $file ) {
            $relative = substr( $file->getPathname(), strlen( $dir ) + 1 );
            if ( 'php' === strtolower( $file->getExtension() ) && ! isset( $files[ $relative ] ) ) {
                $results[] = array( 'file' => bs_relative_path( $file->getPathname() ), 'problem' => 'Not part of this plugin' );
            }
        }
    }

    if ( ! $results ) {
        echo '<p>All plugins match.</p>';
        return;
    }

    echo '<table class="widefat striped">';
    echo '<thead><tr><th>File</th><th>Problem</th></tr></thead>';
    echo '<tbody>';
    foreach ( $results as $row ) {
        echo '<tr>';
        echo '<td><code>' . esc_html( $row['file'] ) . '</code></td>';
        echo '<td>' . esc_html( $row['problem'] ) . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table>';
}