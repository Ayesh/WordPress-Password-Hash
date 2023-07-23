<?php

namespace Ayesh\WP_PasswordHash;

use wpdb;
use function __;
use function add_action;
use function apply_filters;
use function class_exists;
use function defined;
use function hash_equals;
use function is_array;
use function md5;
use function password_get_info;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function strlen;
use function wp_cache_delete;
use const ABSPATH;
use const PASSWORD_DEFAULT;
use const WP_PASSWORD_HASH_ALGO;
use const WP_PASSWORD_HASH_OPTIONS;
use const WPINC;

final class PasswordHash {
	private $algorithm = PASSWORD_DEFAULT;
	private $algorithm_options = [];
	private $wpdb;
	const TEXT_DOMAIN = 'password-hash';

	public function __construct(wpdb $wpdb) {
		$this->wpdb = $wpdb;
		$this->initializePasswordConfig();
	}

	private function initializePasswordConfig() {
		if (defined('WP_PASSWORD_HASH_ALGO')) {
			$this->algorithm = WP_PASSWORD_HASH_ALGO;

			if (defined('WP_PASSWORD_HASH_OPTIONS') && is_array(WP_PASSWORD_HASH_OPTIONS)) {
				$this->algorithm_options = WP_PASSWORD_HASH_OPTIONS;
			}
			$this->algorithm_options = apply_filters( 'wp_php_password_hash_options', $this->algorithm_options );
		}
	}

	public static function setAdminWarning($message) {
		$message = __($message, self::TEXT_DOMAIN);
		add_action( 'admin_notices', static function () use ($message) {
				print "<div class='notice notice-error'><p>{$message}</p></div>";
			}
		);
	}

	/**
	 * Check the user-supplied password against the hash from the database. Falls
	 *  back to core password hashing mechanism if the password hash if of unknown
	 *  format.
	 *
	 * @global PasswordHash $wp_hasher PHPass object used for checking the password
	 *	against the $hash + $password
	 * @uses PasswordHash::CheckPassword
	 *
	 * @param string     $password Plain text user's password
	 * @param string     $hash     Hash of the user's password to check against.
	 * @param string|int $user_id  Optional. User ID.
	 * @return bool False, if the $password does not match the hashed password
	 *
	 */
	public function checkPassword(string $password, string $hash, $user_id = ''): bool {
		// Check if the hash uses Password API.
		$info = password_get_info($hash);
		if (!empty($info['algo'])) {
			return $this->checkPasswordNative($password, $hash, $user_id);
		}

		// Is it god forbid MD5?
		if ( strlen($hash) <= 32 ) {
			return $this->checkPasswordMD5($password, $hash, $user_id);
		}

		// Fallback to PHPass
		return $this->checkPasswordPHPass($password, $hash, $user_id);
	}

	/**
	 * Hash password using @param string $password Plaintext password
	 *
	 * @return false|string
	 *@see password_hash() function.
	 *
	 */
	public function getHash(string $password) {
		return password_hash($password, $this->algorithm, $this->algorithm_options);
	}

	/**
	 * Sets password hash taken from @param string $password password in plain text.
	 *
	 * @param int $user_id User ID of the user.
	 * @return bool|string
	 *@see wp_hash_password().
	 *
	 */
	public function updateHash(string $password, int $user_id) {
		$hash = $this->getHash($password);
		$fields = [ 'user_pass' => &$hash, 'user_activation_key' => '' ];
		$conditions = [ 'ID' => $user_id ];
		$this->wpdb->update($this->wpdb->users, $fields, $conditions);

		wp_cache_delete( $user_id, 'users' );

		return $hash;
	}

	private function checkPasswordNative($password, $hash, $user_id = '') {
		$check = password_verify($password, $hash);
		$rehash = password_needs_rehash($hash, $this->algorithm, $this->algorithm_options);
		return $this->processPasswordCheck($check, $password, $hash, $user_id, $rehash);
	}

	private function checkPasswordMD5($password, $hash, $user_id = '') {
		$check = hash_equals( $hash, md5( $password ) );
		return $this->processPasswordCheck($check, $password, $hash, $user_id);
	}

	private function checkPasswordPHPass($password, $hash, $user_id = '') {
		global $wp_hasher;

		if ( empty($wp_hasher) ) {
			if( !class_exists('PasswordHash') ) {
				require_once ABSPATH . WPINC . '/class-phpass.php';
			}
			$wp_hasher = new \PasswordHash(8, true);
		}

		$check = $wp_hasher->CheckPassword($password, $hash);
		return $this->processPasswordCheck($check, $password, $hash, $user_id);
	}

	private function processPasswordCheck($check, $password, $hash, $user_id, $rehash = true) {
		if ($check && $user_id && $rehash) {
			$hash = $this->updateHash($password, $user_id);
		}

		return apply_filters( 'check_password', $check, $password, $hash, $user_id );
	}
}
