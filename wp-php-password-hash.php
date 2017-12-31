<?php
/**
 * Plugin Name: PHP native password hash
 * Version:     1.0
 * Description: Swaps out Wordpress's password hashing mechanism with PHP 5.5's `password_hash()` functions set, and automatically rehashes the existing passwords on users next successful login. Provides safety against dictionary attacks, time-attacks, brute-force attacks.
 * Licence:     GPLv2 or later
 * Author:      Ayesh Karunaratne
 * Author URI:  https://ayesh.me
 */

if (function_exists('wp_hash_password')) {
  add_action( 'admin_notices', 'wp_password_hash_warn_conflict' );
} elseif (!function_exists('password_hash')) {
  add_action( 'admin_notices', 'wp_password_hash_warn_incompatibility' );
}

if (!function_exists('wp_hash_password') && function_exists('password_hash')) :
/**
 * Check the user-supplied password against the hash from the database. Falls
 *  back to core password hashing mechanism if the password hash if of unknown
 *  format.
 *
 * @global PasswordHash $wp_hasher PHPass object used for checking the password
 *	against the $hash + $password
 * @uses PasswordHash::CheckPassword
 *
 * @param string     $password Plaintext user's password
 * @param string     $hash     Hash of the user's password to check against.
 * @param string|int $user_id  Optional. User ID.
 * @return bool False, if the $password does not match the hashed password
 *
 */
function wp_check_password( $password, $hash, $user_id = '' ) {
  // Check if the current hash is known by PHP natively.
  $info = password_get_info($hash);
  if (!empty($info['algo'])) {
    $check = password_verify($password, $hash);
    if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
      $hash = wp_set_password($password, $user_id);
    }

    return apply_filters( 'check_password', $check, $password, $hash, $user_id );
  }

  // This part is copied from the WP core password verification function.
  global $wp_hasher;

  // If the hash is still md5...
  if ( strlen($hash) <= 32 ) {
    $check = hash_equals( $hash, md5( $password ) );
    if ( $check && $user_id ) {
      // Rehash using new hash.
      wp_set_password($password, $user_id);
      $hash = wp_hash_password($password);
    }

    return apply_filters( 'check_password', $check, $password, $hash, $user_id );
  }

  //if class doesnt exist, pull it in
  if(!class_exists("PasswordHash")) {
    require_once ABSPATH . WPINC . '/class-phpass.php';
  }

  // If the stored hash is longer than an MD5, presume the
  // new style phpass portable hash.
  if ( empty($wp_hasher) ) {
    // By default, use the portable hash from phpass
    $wp_hasher = new PasswordHash(8, true);
  }

  $check = $wp_hasher->CheckPassword($password, $hash);
  if ($check) {
    // If the password is correct, rehash it to the new format.
    wp_set_password($password, $user_id);
    $hash = wp_hash_password($password);
  }

  /** documented in wp-includes/pluggable.php */
  return apply_filters( 'check_password', $check, $password, $hash, $user_id );
}


/**
 * Hash password using @see password_hash() function if available.
 *
 * @param string $password Plaintext password
 * @return false|string
 */
function wp_hash_password( $password ) {
  $options = apply_filters( 'wp_php_password_hash_options', array() );
  return password_hash( $password, PASSWORD_DEFAULT, $options );
}

/**
 * Sets password hash taken from @see wp_hash_password().
 *
 * @param string $password password in plaintext.
 * @param int $user_id User ID of the user.
 * @return bool|string
 */
function wp_set_password( $password, $user_id ) {
  /**
   * @var \wpdb $wpdb
   */
  global $wpdb;

  $hash = wp_hash_password($password);
  $fields = array('user_pass' => &$hash, 'user_activation_key' => '');
  $conditions = array('ID' => $user_id);
  $wpdb->update($wpdb->users, $fields, $conditions);

  wp_cache_delete( $user_id, 'users' );

  return $hash;
}

endif;

function wp_password_hash_warn_incompatibility() {
  wp_password_hash_set_message('Your current system configuration does support password hashing with password_hash() function. Please upgrade your PHP version to PHP 5.5 or later, or disable the "PHP native password hash" plugin.');
}

function wp_password_hash_warn_conflict() {
  wp_password_hash_set_message('Another plugin has already overridden the password hashing mechanism. The "PHP native password hash" plugin will not work.');
}

function wp_password_hash_set_message($message) {
  $class = 'notice notice-error';
  $message = __( $message );

  printf( '<div class="%1$s"><p>%2$s</p></div>', $class, $message );
}
