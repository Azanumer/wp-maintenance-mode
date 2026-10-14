<?php
/**
 * Plugin Name: WP Maintenance Mode
 * Description: Lightweight maintenance mode with 503 + Retry-After, admin bypass cookie, IP whitelist, auto-off timer, and a customizable holding page. No JavaScript, no bloat.
 * Version:     1.0.0
 * Author:      Azan Umer
 * License:     MIT
 * License URI: https://opensource.org/licenses/MIT
 * Text Domain: wp-maintenance-mode
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WMM_VERSION', '1.0.0' );
define( 'WMM_OPTION', 'wmm_settings' );

/**
 * Get all settings with sane defaults.
 *
 * @return array
 */
function wmm_get_settings() {
    $defaults = array(
        'enabled'     => 0,
        'title'       => 'We&rsquo;ll be right back',
        'message'     => 'We are performing scheduled maintenance. Please check back soon.',
        'retry_after' => 3600, // seconds — sent as the Retry-After header
        'auto_off'    => 0,    // unix timestamp; 0 = never auto-disable
        'allowed_ips' => '',   // one per line, supports CIDR (e.g. 203.0.113.0/24)
    );
    return wp_parse_args( (array) get_option( WMM_OPTION, array() ), $defaults );
}

/**
 * Name of the signed bypass cookie.
 *
 * @return string
 */
function wmm_cookie_name() {
    // Tie the cookie to the site so it cannot leak across installs.
    return 'wmm_bypass_' . substr( md5( home_url() ), 0, 10 );
}

/**
 * Sign a value with the site's secret keys so the cookie can't be forged.
 *
 * @param string $value
 * @return string
 */
function wmm_sign( $value ) {
    $secret = wp_salt( 'auth' );
    return hash_hmac( 'sha256', $value, $secret );
}

/**
 * Set (or clear) the bypass cookie for the current user.
 *
 * @param bool $set
 */
function wmm_set_bypass_cookie( $set = true ) {
    $name = wmm_cookie_name();
    if ( $set && current_user_can( 'manage_options' ) ) {
        $value = '1|' . time() . '|' . wmm_sign( '1' );
        setcookie( $name, $value, time() + YEAR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
        $_COOKIE[ $name ] = $value; // make it visible to this request
    } else {
        setcookie( $name, '', time() - HOUR_IN_SECONDS, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
        unset( $_COOKIE[ $name ] );
    }
}

/**
 * Whether the current visitor may bypass maintenance mode.
 *
 * @return bool
 */
function wmm_has_bypass() {
    if ( current_user_can( 'manage_options' ) ) {
        return true;
    }
    $name = wmm_cookie_name();
    if ( empty( $_COOKIE[ $name ] ) ) {
        return false;
    }
    $parts = explode( '|', $_COOKIE[ $name ] );
    if ( count( $parts ) !== 3 ) {
        return false;
    }
    list( $flag, $ts, $sig ) = $parts;
    return '1' === $flag && hash_equals( wmm_sign( '1' ), $sig );
}

/**
 * Check an IP against an allow-list that may contain plain IPs or CIDR ranges.
 *
 * @param string $ip
 * @param array  $list
 * @return bool
 */
function wmm_ip_allowed( $ip, $list ) {
    $bin = @inet_pton( $ip );
    if ( false === $bin ) {
        return false;
    }
    foreach ( $list as $entry ) {
        $entry = trim( $entry );
        if ( '' === $entry ) {
            continue;
        }
        if ( strpos( $entry, '/' ) !== false ) {
            list( $net, $bits ) = explode( '/', $entry, 2 );
            $net_bin = @inet_pton( $net );
            if ( false === $net_bin || strlen( $net_bin ) !== strlen( $bin ) ) {
                continue;
            }
            $bits = (int) $bits;
            $mask = str_repeat( 'f', (int) floor( $bits / 4 ) );
            switch ( $bits % 4 ) {
                case 1: $mask .= '8'; break;
                case 2: $mask .= 'c'; break;
                case 3: $mask .= 'e'; break;
            }
            $mask = str_pad( $mask, strlen( $bin ) * 2, '0' );
            $mask_bin = pack( 'H*', $mask );
            if ( ( $bin & $mask_bin ) === ( $net_bin & $mask_bin ) ) {
                return true;
            }
        } elseif ( $entry === $ip ) {
            return true;
        }
    }
    return false;
}

/**
 * Decide whether to show the maintenance page on this request.
 */
function wmm_maybe_serve() {
    if ( defined( 'WP_CLI' ) && WP_CLI ) {
        return;
    }
    if ( is_admin() || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
        return;
    }
    // Never block the login page itself or preview requests from admins.
    if ( isset( $GLOBALS['pagenow'] ) && 'wp-login.php' === $GLOBALS['pagenow'] ) {
        return;
    }
    if ( isset( $_GET['wmm_preview'] ) && current_user_can( 'manage_options' ) ) {
        wmm_serve();
    }

    $settings = wmm_get_settings();

    if ( empty( $settings['enabled'] ) ) {
        return;
    }

    // Auto-off: disable once the timer has passed so maintenance never gets stuck on.
    if ( ! empty( $settings['auto_off'] ) && time() >= (int) $settings['auto_off'] ) {
        $settings['enabled']  = 0;
        $settings['auto_off'] = 0;
        update_option( WMM_OPTION, $settings );
        return;
    }

    if ( wmm_has_bypass() ) {
        return;
    }

    $allowed = array_filter( array_map( 'trim', explode( "\n", (string) $settings['allowed_ips'] ) ) );
    if ( ! empty( $allowed ) ) {
        $visitor_ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
        if ( wmm_ip_allowed( $visitor_ip, $allowed ) ) {
            return;
        }
    }

    wmm_serve();
}
add_action( 'template_redirect', 'wmm_maybe_serve', 1 );

/**
 * Output the maintenance page with a 503 status and Retry-After header.
 */
function wmm_serve() {
    $settings    = wmm_get_settings();
    $retry_after = max( 60, (int) $settings['retry_after'] );

    status_header( 503 );
    nocache_headers();
    header( 'Retry-After: ' . $retry_after );

    $title   = wp_kses_post( $settings['title'] );
    $message = wp_kses_post( $settings['message'] );
    ?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?php echo esc_html( wp_strip_all_tags( $settings['title'] ) ); ?> &mdash; <?php bloginfo( 'name' ); ?></title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: radial-gradient(circle at 50% 30%, #1e293b, #0f172a); color: #e2e8f0; padding: 24px; }
  .card { max-width: 520px; text-align: center; }
  .dot { width: 64px; height: 64px; margin: 0 auto 24px; border-radius: 50%;
         border: 4px solid #334155; border-top-color: #38bdf8;
         animation: spin 1.2s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 1.9rem; margin-bottom: 12px; font-weight: 700; }
  p { color: #94a3b8; line-height: 1.6; }
  .eta { margin-top: 16px; font-size: .85rem; color: #64748b; }
</style>
</head>
<body>
  <div class="card">
    <div class="dot" aria-hidden="true"></div>
    <h1><?php echo $title; ?></h1>
    <p><?php echo $message; ?></p>
    <p class="eta">HTTP 503 — retry in about <?php echo esc_html( human_time_diff( time(), time() + $retry_after ) ); ?></p>
  </div>
</body>
</html>
    <?php
    exit;
}

/* -------------------------------------------------------------------------
 * Admin settings
 * ------------------------------------------------------------------------- */

/**
 * Register the settings page.
 */
function wmm_admin_menu() {
    add_options_page(
        __( 'Maintenance Mode', 'wp-maintenance-mode' ),
        __( 'Maintenance Mode', 'wp-maintenance-mode' ),
        'manage_options',
        'wmm-settings',
        'wmm_settings_page'
    );
}
add_action( 'admin_menu', 'wmm_admin_menu' );

/**
 * When an admin enables maintenance mode, drop them a bypass cookie so they
 * can keep working while everyone else sees the holding page.
 */
function wmm_admin_init() {
    register_setting( 'wmm_settings_group', WMM_OPTION, array(
        'sanitize_callback' => 'wmm_sanitize',
    ) );
}
add_action( 'admin_init', 'wmm_admin_init' );

/**
 * Sanitize settings on save.
 *
 * @param array $input
 * @return array
 */
function wmm_sanitize( $input ) {
    $out = array();
    $out['enabled']     = ! empty( $input['enabled'] ) ? 1 : 0;
    $out['title']       = isset( $input['title'] ) ? wp_kses_post( $input['title'] ) : '';
    $out['message']     = isset( $input['message'] ) ? wp_kses_post( $input['message'] ) : '';
    $out['retry_after'] = max( 60, (int) ( $input['retry_after'] ?? 3600 ) );
    $out['auto_off']    = 0;
    if ( ! empty( $input['auto_off_hours'] ) ) {
        $hours = max( 1, min( 168, (int) $input['auto_off_hours'] ) );
        $out['auto_off'] = time() + $hours * HOUR_IN_SECONDS;
    } elseif ( ! empty( $input['auto_off_keep'] ) && ! empty( $input['auto_off_current'] ) ) {
        $out['auto_off'] = (int) $input['auto_off_current'];
    }
    $out['allowed_ips'] = isset( $input['allowed_ips'] ) ? sanitize_textarea_field( $input['allowed_ips'] ) : '';

    if ( $out['enabled'] ) {
        add_action( 'shutdown', function () {
            wmm_set_bypass_cookie( true );
        } );
    } else {
        add_action( 'shutdown', function () {
            wmm_set_bypass_cookie( false );
        } );
    }
    return $out;
}

/**
 * Render the settings page.
 */
function wmm_settings_page() {
    $s = wmm_get_settings();
    ?>
<div class="wrap">
  <h1><?php esc_html_e( 'Maintenance Mode', 'wp-maintenance-mode' ); ?></h1>
  <?php if ( ! empty( $s['enabled'] ) ) : ?>
    <div class="notice notice-warning inline">
      <p><strong><?php esc_html_e( 'Maintenance mode is ON.', 'wp-maintenance-mode' ); ?></strong>
      <a href="<?php echo esc_url( home_url( '/?wmm_preview=1' ) ); ?>" target="_blank"><?php esc_html_e( 'Preview the page', 'wp-maintenance-mode' ); ?></a></p>
    </div>
  <?php endif; ?>
  <form method="post" action="options.php">
    <?php settings_fields( 'wmm_settings_group' ); ?>
    <table class="form-table">
      <tr>
        <th scope="row"><?php esc_html_e( 'Enable', 'wp-maintenance-mode' ); ?></th>
        <td><label><input type="checkbox" name="<?php echo esc_attr( WMM_OPTION ); ?>[enabled]" value="1" <?php checked( $s['enabled'], 1 ); ?>>
        <?php esc_html_e( 'Put the site into maintenance mode', 'wp-maintenance-mode' ); ?></label></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Page title', 'wp-maintenance-mode' ); ?></th>
        <td><input type="text" class="regular-text" name="<?php echo esc_attr( WMM_OPTION ); ?>[title]" value="<?php echo esc_attr( $s['title'] ); ?>"></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Message', 'wp-maintenance-mode' ); ?></th>
        <td><textarea class="large-text" rows="3" name="<?php echo esc_attr( WMM_OPTION ); ?>[message]"><?php echo esc_textarea( $s['message'] ); ?></textarea></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Retry-After (seconds)', 'wp-maintenance-mode' ); ?></th>
        <td><input type="number" min="60" step="60" name="<?php echo esc_attr( WMM_OPTION ); ?>[retry_after]" value="<?php echo esc_attr( $s['retry_after'] ); ?>">
        <p class="description"><?php esc_html_e( 'Sent as the Retry-After header so search engines know when to come back.', 'wp-maintenance-mode' ); ?></p></td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Auto-disable after', 'wp-maintenance-mode' ); ?></th>
        <td>
          <?php if ( ! empty( $s['auto_off'] ) ) : ?>
            <p><?php printf( esc_html__( 'Scheduled to turn off: %s', 'wp-maintenance-mode' ), esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $s['auto_off'] ) ) ); ?></p>
            <input type="hidden" name="<?php echo esc_attr( WMM_OPTION ); ?>[auto_off_current]" value="<?php echo esc_attr( $s['auto_off'] ); ?>">
            <label><input type="checkbox" name="<?php echo esc_attr( WMM_OPTION ); ?>[auto_off_keep]" value="1" checked> <?php esc_html_e( 'Keep existing schedule', 'wp-maintenance-mode' ); ?></label>
            <p class="description"><?php esc_html_e( 'Or set a new one below (overrides).', 'wp-maintenance-mode' ); ?></p>
          <?php endif; ?>
          <input type="number" min="1" max="168" name="<?php echo esc_attr( WMM_OPTION ); ?>[auto_off_hours]" placeholder="<?php esc_attr_e( 'Hours (leave empty = never)', 'wp-maintenance-mode' ); ?>">
        </td>
      </tr>
      <tr>
        <th scope="row"><?php esc_html_e( 'Allowed IPs', 'wp-maintenance-mode' ); ?></th>
        <td><textarea class="large-text code" rows="3" name="<?php echo esc_attr( WMM_OPTION ); ?>[allowed_ips]"><?php echo esc_textarea( $s['allowed_ips'] ); ?></textarea>
        <p class="description"><?php esc_html_e( 'One IP or CIDR range per line. These visitors skip maintenance mode.', 'wp-maintenance-mode' ); ?></p></td>
      </tr>
    </table>
    <?php submit_button(); ?>
  </form>
  <p class="description"><?php esc_html_e( 'Tip: admins automatically get a signed bypass cookie when they enable maintenance mode, so you can keep working on the site while visitors see the holding page.', 'wp-maintenance-mode' ); ?></p>
</div>
    <?php
}

/**
 * Drop the bypass cookie the moment an admin turns maintenance on, and clear
 * it when they turn it off.
 */
function wmm_cookie_on_toggle( $old, $new ) {
    if ( is_array( $new ) && ! empty( $new['enabled'] ) ) {
        wmm_set_bypass_cookie( true );
    } elseif ( is_array( $new ) && empty( $new['enabled'] ) ) {
        wmm_set_bypass_cookie( false );
    }
}
add_action( 'update_option_' . WMM_OPTION, 'wmm_cookie_on_toggle', 10, 2 );
