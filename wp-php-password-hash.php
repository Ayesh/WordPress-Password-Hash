<?php
/**
 * Plugin Name: PHP native password hash
 * Version:     2.1
 * Description: Swaps out WordPress's password hashing mechanism with PHP 5.5's `password_hash()` functions set, and automatically rehashes the existing passwords on users next successful login. Provides safety against dictionary attacks, time-attacks, brute-force attacks.
 * Licence:     GPLv2 or later
 * Author:      Ayesh Karunaratne
 * Author URI:  https://ayesh.me/open-source
 */

if ( function_exists( 'wp_hash_password' ) ) {
	$hasher = wp_password_hash_include();
	$hasher::setAdminWarning( 'Another plugin has already overridden the password hashing mechanism. The "PHP native password hash" plugin will not work.' );
} elseif ( ! function_exists( 'password_hash' ) ) {
	$hasher = wp_password_hash_include();
	$hasher::setAdminWarning( 'Your current system configuration does support password hashing with password_hash() function. Please upgrade your PHP version to PHP 5.5 or later, or disable the "PHP native password hash" plugin.' );
}

/**
 * @return \Ayesh\WP_PasswordHash\PasswordHash
 */
function wp_password_hash_include() {
	static $hasher;
	require_once __DIR__ . '/src/PasswordHash.php';
	if ( ! $hasher ) {
		global $wpdb;
		$hasher = new \Ayesh\WP_PasswordHash\PasswordHash( $wpdb );
	}

	return $hasher;
}

/**
 * The function calls below override the WordPress-provided functions.
 *
 * All of the plugin functionality is contained in @see
 * \Ayesh\WP_PasswordHash\PasswordHash class. Check the called proxy method for
 * further documentation.
 */

if ( ! function_exists( 'wp_hash_password' ) && function_exists( 'password_hash' ) ) :

	function wp_check_password( $password, $hash, $user_id = '' ) {
		$hasher = wp_password_hash_include();
		return $hasher->checkPassword( $password, $hash, $user_id );
	}

	function wp_hash_password( $password ) {
		$hasher = wp_password_hash_include();
		return $hasher->getHash( $password );
	}

	function wp_set_password( $password, $user_id ) {
		$hasher = wp_password_hash_include();
		return $hasher->updateHash( $password, $user_id );
	}

endif;
