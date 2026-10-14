<?php
/**
 * Uninstall cleanup for WP Maintenance Mode.
 */
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'wmm_settings' );
