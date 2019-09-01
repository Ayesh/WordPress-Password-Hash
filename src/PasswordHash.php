<?php


namespace Ayesh\WP_PasswordHash;


class PasswordHash {
	private $algorithm = \PASSWORD_DEFAULT;
	private $wpdb;
	const TEXT_DOMAIN = 'password-hash';

	public function __construct(\wpdb $wpdb) {
		$this->wpdb = $wpdb;
		$this->initializePasswordConfig();
	}

	private function initializePasswordConfig() {
		if (defined('WP_PASSWORD_HASH_ALGO')) {
			if (!defined(\WP_PASSWORD_HASH_ALGO)) {
				self::setAdminWarning('You have set the configuration option "WP_PASSWORD_HASH_ALGO" to a password algorithm that does not exist. PHP default passwor hashing algorithm will be used.');
			}
			$this->algorithm = \WP_PASSWORD_HASH_ALGO;
		}
	}

	public static function setAdminWarning($message) {
		$message = __($message, self::TEXT_DOMAIN);
		add_action( 'admin_notices', static function () use ($message) {
			print "<div class='notice notice-error'>{__($message)}</div>";
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
	public function checkPassword($password, $hash, $user_id = '') {
		// Check if the current hash is known by PHP natively.
		$info = password_get_info($hash);
		if (!empty($info['algo'])) {
			$check = password_verify($password, $hash);
			if ($check && password_needs_rehash($hash, PASSWORD_DEFAULT)) {
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

		// If the stored hash is longer than an MD5, presume the
		// new style phpass portable hash.
		if ( empty($wp_hasher) ) {
			// If class is not loaded, load it first.
			if( !class_exists('PasswordHash') ) {
				require_once ABSPATH . WPINC . '/class-phpass.php';
			}
			// By default, use the portable hash from phpass
			$wp_hasher = new \PasswordHash(8, true);
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
	 * Hash password using @see password_hash() function.
	 *
	 * @param string $password Plaintext password
	 * @return false|string
	 */
	public function getHash($password) {
		$options = apply_filters( 'wp_php_password_hash_options', array() );
		return password_hash( $password, $this->algorithm, $options );
	}

	/**
	 * Sets password hash taken from @see wp_hash_password().
	 *
	 * @param string $password password in plain text.
	 * @param int $user_id User ID of the user.
	 * @return bool|string
	 */
	public function storeHash($password, $user_id) {
		$hash = $this->getHash($password);
		$fields = [ 'user_pass' => &$hash, 'user_activation_key' => '' ];
		$conditions = [ 'ID' => $user_id ];
		$this->wpdb->update($this->wpdb->users, $fields, $conditions);

		wp_cache_delete( $user_id, 'users' );

		return $hash;
	}
}
