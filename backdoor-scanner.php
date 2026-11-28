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

add_action( 'admin_post_bs_clear_cron', 'bs_handle_clear_cron' );

add_action( 'admin_post_bs_quarantine', 'bs_handle_quarantine' );

add_action( 'admin_post_bs_restore', 'bs_handle_restore' );

add_action( 'admin_post_bs_remove_admin', 'bs_handle_remove_admin' );

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
    $notice_key = 'bs_notice_' . get_current_user_id();
    $notice     = get_transient( $notice_key );
    if ( $notice ) {
        delete_transient( $notice_key );
        echo '<div class="notice notice-success"><p>' . esc_html( $notice ) . '</p></div>';
    }
    echo '<h2>Admin users</h2>';
    echo '<table class="widefat striped">';
    echo '<thead><tr><th>Username</th><th>Email</th><th>Registered</th><th>Action</th></tr></thead>';
    echo '<tbody>';

    foreach ( $admins as $admin ) {
        echo '<tr>';
        echo '<td>' . esc_html( $admin->user_login ) . '</td>';
        echo '<td>' . esc_html( $admin->user_email ) . '</td>';
        echo '<td>' . esc_html( $admin->user_registered ) . '</td>';
        if ( get_current_user_id() === $admin->ID ) {
            echo '<td><em>You</em></td>';
        } else {
            echo '<td>' . bs_action_button( 'bs_remove_admin', array( 'user_id' => $admin->ID ), 'Remove', 'Delete the admin ' . $admin->user_login . '? Their posts will be moved to you.' ) . '</td>';
        }
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
    echo '<thead><tr><th>Hook</th><th>Next run</th><th>Repeats</th><th>Runs</th><th>Action</th></tr></thead>';
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
                echo '<td>' . bs_action_button( 'bs_clear_cron', array( 'hook' => $hook ), 'Remove', 'Remove every scheduled run of ' . $hook . '?' ) . '</td>';

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
    echo '<thead>';
    echo '<tr>';
    echo '<th>File</th>';
    echo '<th>Line</th>';
    echo '<th>Found</th>';
    echo '<th>Code</th>';
    echo '<th>Action</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';

    $uploads_rel = bs_relative_path( $uploads['basedir'] ) . '/';
    $mu_rel      = bs_relative_path( WPMU_PLUGIN_DIR ) . '/';
    $shown       = array();

    foreach ( $results as $row ) {
        $action = '';
        $whole  = 0 === strpos( $row['file'], $uploads_rel ) || 0 === strpos( $row['file'], $mu_rel );

        if ( $whole && ! isset( $shown[ $row['file'] ] ) ) {
            $shown[ $row['file'] ] = true;   // one button per file, even if it has several bad lines
            $action = bs_quarantine_button( $row['file'] );
        } elseif ( ! $whole ) {
            $action = '<em>Reinstall the theme</em>';
        }

        echo '<tr>';
        echo '<td><code>' . esc_html( $row['file'] ) . '</code></td>';
        echo '<td>' . esc_html( $row['line'] ) . '</td>';
        echo '<td>' . esc_html( $row['match'] ) . '</td>';
        echo '<td><code>' . esc_html( $row['code'] ) . '</code></td>';
        echo '<td>' . $action . '</td>';
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

// The official md5 list for this WordPress version. Falls back to en_US if the site's language has none.
function bs_core_checksums() {
    global $wp_version;

    // get_core_checksums() lives in an admin file that isn't always loaded.
    require_once ABSPATH . 'wp-admin/includes/update.php';

    $checksums = get_core_checksums( $wp_version, get_locale() );
    if ( ! $checksums && 'en_US' !== get_locale() ) {
        $checksums = get_core_checksums( $wp_version, 'en_US' );
    }
    return $checksums;
}

function bs_render_core_section() {
    global $wp_version;

    $checksums = bs_core_checksums();

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
    echo '<thead><tr><th>File</th><th>Problem</th><th>Action</th></tr></thead>';
    echo '<tbody>';

    foreach ( $results as $row ) {
        echo '<tr>';
        echo '<td><code>' . esc_html( $row['file'] ) . '</code></td>';
        echo '<td>' . esc_html( $row['problem'] ) . '</td>';
        echo '<td>' . bs_row_action( $row, 'core' ) . '</td>';
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
    echo '<thead><tr><th>File</th><th>Problem</th><th>Action</th></tr></thead>';
    echo '<tbody>';
    foreach ( $results as $row ) {
        echo '<tr>';
        echo '<td><code>' . esc_html( $row['file'] ) . '</code></td>';
        echo '<td>' . esc_html( $row['problem'] ) . '</td>';
        echo '<td>' . bs_row_action( $row, 'plugin' ) . '</td>';
        echo '</tr>';
    }
    echo '</tbody></table>';
}

// A small form with one button. Every action uses this, so each one gets a nonce and a confirm dialog.
function bs_action_button( $action, $fields, $label, $confirm ) {
    $html  = '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"';
    $html .= ' onsubmit="return confirm(' . esc_attr( wp_json_encode( $confirm ) ) . ');">';
    $html .= '<input type="hidden" name="action" value="' . esc_attr( $action ) . '">';
    foreach ( $fields as $name => $value ) {
        $html .= '<input type="hidden" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '">';
    }
    $html .= wp_nonce_field( $action, '_wpnonce', true, false );
    $html .= '<button type="submit" class="button button-small">' . esc_html( $label ) . '</button>';
    $html .= '</form>';
    return $html;
}

function bs_handle_clear_cron() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'You are not allowed to do this.' );
    }
    check_admin_referer( 'bs_clear_cron' );

    $hook  = isset( $_POST['hook'] ) ? sanitize_text_field( wp_unslash( $_POST['hook'] ) ) : '';
    $count = wp_unschedule_hook( $hook );

    bs_redirect_with_notice( 'Removed ' . (int) $count . ' scheduled run(s) of ' . $hook . '.' );
}

// Show a one-time message on the scanner page, then send the browser back there.
function bs_redirect_with_notice( $message ) {
    set_transient( 'bs_notice_' . get_current_user_id(), $message, 60 );
    wp_safe_redirect( admin_url( 'tools.php?page=backdoor-scanner' ) );
    exit;
}

function bs_quarantine_button( $file ) {
    return bs_action_button(
        'bs_quarantine',
        array( 'file' => $file ),
        'Quarantine',
        'Move ' . $file . ' to quarantine? It stops running, and a copy is kept so it can be put back.'
    );
}

// Extra files get Quarantine. Changed or missing official files get Restore.
function bs_row_action( $row, $type ) {
    if ( 0 === strpos( $row['problem'], 'Not part of' ) ) {
        return bs_quarantine_button( $row['file'] );
    }
    if ( in_array( $row['problem'], array( 'Changed', 'Missing' ), true ) ) {
        return bs_action_button(
            'bs_restore',
            array( 'file' => $row['file'], 'type' => $type ),
            'Restore',
            'Replace ' . $row['file'] . ' with the official copy from WordPress.org? The current version is saved in quarantine first.'
        );
    }
    return '';
}

// Makes the quarantine folder if needed and returns a dated .txt path in it.
// .txt so the server can never run it, and the date so nothing gets overwritten.
function bs_quarantine_path( $relative ) {
    $dir = WP_CONTENT_DIR . '/bs-quarantine';
    if ( ! is_dir( $dir ) ) {
        wp_mkdir_p( $dir );
        file_put_contents( $dir . '/.htaccess', "Require all denied\n" );
    }
    return $dir . '/' . gmdate( 'Ymd-His' ) . '-' . str_replace( '/', '__', $relative ) . '.txt';
}

function bs_handle_quarantine() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'You are not allowed to do this.' );
    }
    check_admin_referer( 'bs_quarantine' );

    $relative = isset( $_POST['file'] ) ? wp_unslash( $_POST['file'] ) : '';
    $root     = trailingslashit( realpath( ABSPATH ) );
    $path     = realpath( ABSPATH . $relative );

    // realpath() resolves tricks like ../ so a request can't point outside the WordPress folder.
    if ( ! $path || 0 !== strpos( $path, $root ) || ! is_file( $path ) ) {
        bs_redirect_with_notice( 'Could not find ' . $relative . '.' );
    }
    if ( 'wp-config.php' === basename( $path ) || 0 === strpos( $path, realpath( __DIR__ ) ) ) {
        bs_redirect_with_notice( 'That file is not allowed to be quarantined.' );
    }

    $target = bs_quarantine_path( $relative );

    if ( ! rename( $path, $target ) ) {
        bs_redirect_with_notice( 'Could not move ' . $relative . '. Check file permissions.' );
    }

    $log   = get_option( 'bs_quarantine_log', array() );
    $log[] = array(
        'file'  => $relative,
        'moved' => bs_relative_path( $target ),
        'time'  => time(),
        'user'  => get_current_user_id(),
    );
    update_option( 'bs_quarantine_log', $log, false );

    bs_redirect_with_notice( 'Moved ' . $relative . ' to quarantine.' );
}

// Where to download a clean core file, and the md5 it must have.
function bs_core_source( $relative ) {
    global $wp_version;

    $checksums = bs_core_checksums();
    if ( ! isset( $checksums[ $relative ] ) || 0 === strpos( $relative, 'wp-content/' ) ) {
        return new WP_Error( 'bs_restore', $relative . ' is not a WordPress core file.' );
    }
    return array(
        'url' => 'https://core.svn.wordpress.org/tags/' . $wp_version . '/' . $relative,
        'md5' => array( $checksums[ $relative ] ),
    );
}

// Same for a plugin file. The slug comes from the folder name, the version from the installed plugin.
function bs_plugin_source( $relative ) {
    require_once ABSPATH . 'wp-admin/includes/plugin.php';

    $prefix = bs_relative_path( WP_PLUGIN_DIR ) . '/';
    if ( 0 !== strpos( $relative, $prefix ) ) {
        return new WP_Error( 'bs_restore', $relative . ' is not in the plugins folder.' );
    }

    // wp-content/plugins/akismet/class.akismet.php becomes akismet and class.akismet.php.
    list( $slug, $file ) = array_pad( explode( '/', substr( $relative, strlen( $prefix ) ), 2 ), 2, '' );

    $version = '';
    foreach ( get_plugins() as $plugin_file => $plugin ) {
        if ( dirname( $plugin_file ) === $slug ) {
            $version = $plugin['Version'];
        }
    }
    if ( ! $version ) {
        return new WP_Error( 'bs_restore', 'Could not find the installed version of ' . $slug . '.' );
    }

    $response = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . $slug . '/' . $version . '.json' );
    $data     = json_decode( wp_remote_retrieve_body( $response ), true );
    if ( ! isset( $data['files'][ $file ]['md5'] ) ) {
        return new WP_Error( 'bs_restore', $file . ' is not in the official file list for ' . $slug . ' ' . $version . '.' );
    }

    // Some plugins only publish to trunk. If this tag doesn't exist, the download fails and we refuse.
    return array(
        'url' => 'https://plugins.svn.wordpress.org/' . $slug . '/tags/' . $version . '/' . $file,
        'md5' => (array) $data['files'][ $file ]['md5'],
    );
}

function bs_handle_restore() {
    if ( ! current_user_can( 'manage_options' ) ) {
        wp_die( 'You are not allowed to do this.' );
    }
    check_admin_referer( 'bs_restore' );

    $relative = isset( $_POST['file'] ) ? wp_unslash( $_POST['file'] ) : '';
    $type     = isset( $_POST['type'] ) ? wp_unslash( $_POST['type'] ) : '';

    $source = ( 'plugin' === $type ) ? bs_plugin_source( $relative ) : bs_core_source( $relative );
    if ( is_wp_error( $source ) ) {
        bs_redirect_with_notice( $source->get_error_message() );
    }

    // A missing file has no realpath, so check its folder instead. The folder must be inside WordPress.
    $root = trailingslashit( realpath( ABSPATH ) );
    $dir  = realpath( dirname( ABSPATH . $relative ) );
    if ( ! $dir || 0 !== strpos( trailingslashit( $dir ), $root ) ) {
        bs_redirect_with_notice( 'Could not find the folder for ' . $relative . '.' );
    }
    $path = $dir . '/' . basename( $relative );

    // A symlink could point the write somewhere else, so refuse those too.
    if ( 'wp-config.php' === basename( $path ) || is_link( $path )
        || 0 === strpos( trailingslashit( $dir ), trailingslashit( realpath( __DIR__ ) ) ) ) {
        bs_redirect_with_notice( 'That file is not allowed to be restored.' );
    }

    // Only write the download if it matches the official checksum.
    $response = wp_remote_get( $source['url'], array( 'timeout' => 20 ) );
    $body     = wp_remote_retrieve_body( $response );
    if ( 200 !== wp_remote_retrieve_response_code( $response ) || ! in_array( md5( $body ), $source['md5'], true ) ) {
        bs_redirect_with_notice( 'Could not get a copy of ' . $relative . ' that matches the official checksum. Nothing was changed.' );
    }

    // Keep the infected version as evidence.
    $note = '';
    if ( file_exists( $path ) ) {
        if ( ! copy( $path, bs_quarantine_path( $relative ) ) ) {
            bs_redirect_with_notice( 'Could not save a copy of ' . $relative . ' first. Nothing was changed.' );
        }
        $note = ' The old version was saved in bs-quarantine.';
    }

    if ( false === file_put_contents( $path, $body ) ) {
        bs_redirect_with_notice( 'Could not write ' . $relative . '. Check file permissions.' );
    }

    bs_redirect_with_notice( 'Restored ' . $relative . ' from WordPress.org.' . $note );
}

function bs_handle_remove_admin() {
    if ( ! current_user_can( 'delete_users' ) ) {
        wp_die( 'You are not allowed to do this.' );
    }
    check_admin_referer( 'bs_remove_admin' );

    $user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : 0;
    $user    = get_userdata( $user_id );

    if ( ! $user ) {
        bs_redirect_with_notice( 'Could not find that user.' );
    }
    // Deleting yourself would lock you out.
    if ( get_current_user_id() === $user_id ) {
        bs_redirect_with_notice( 'You cannot remove your own account.' );
    }
    // This button is only for admins. Other users are managed on the normal Users page.
    if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
        bs_redirect_with_notice( $user->user_login . ' is not an admin.' );
    }

    // wp_delete_user() lives in an admin file that isn't always loaded.
    require_once ABSPATH . 'wp-admin/includes/user.php';

    // The second argument moves their posts to you instead of deleting them.
    if ( ! wp_delete_user( $user_id, get_current_user_id() ) ) {
        bs_redirect_with_notice( 'Could not remove ' . $user->user_login . '.' );
    }

    bs_redirect_with_notice( 'Removed the admin ' . $user->user_login . '. Their posts now belong to you.' );
}