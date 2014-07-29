<?php
/*
   Plugin Name: IMAP Authentication 2
   Version: 1.4
   Plugin URI: http://blog.neverusethisfont.com/2009/02/imap-authentication-for-wordpress-271/
   Description: Authenticate users using IMAP authentication. For Wordpress 3.7.0
   Author: Aaron Parecki
   Author URI: http://www.aaronparecki.com


   Copyright 2009 by Aaron Parecki  (email : aaron@parecki.com)
   Copyright 2013 by Unbit sas (author: Riccardo Magliocchetti)

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

add_action('admin_menu', array('IMAPAuthentication', 'admin_menu'));
//add_action('lost_password', array('IMAPAuthentication', 'disable_password'));
//add_action('retrieve_password', array('IMAPAuthentication', 'disable_password'));
//add_action('password_reset', array('IMAPAuthentication', 'disable_password'));
//add_filter('show_password_fields', array('IMAPAuthentication', 'show_password_fields'));
add_filter('authenticate', array('IMAPAuthentication', 'authenticate'), 1, 3);

if( is_plugin_page() ) {
	$mailbox = IMAPAuthentication::get_mailbox();
	$user_suffix = IMAPAuthentication::get_user_suffix();
	?>
		<div class="wrap">
		<h2>IMAP Authentication Options</h2>
		<form name="imapauthenticationoptions" method="post" action="options.php">
		<?php wp_nonce_field('update-options'); ?>
		<input type="hidden" name="action" value="update" />
		<input type="hidden" name="page_options" value="imap_authentication_mailbox,imap_authentication_user_suffix" />
		<fieldset class="options">
		<table width="100%" cellspacing="2" cellpadding="5" class="form-table">
		<tr valign="top">
		<th width="33%" scope="row"><label for="imap_authentication_mailbox">Mailbox</label></th>
		<td><input name="imap_authentication_mailbox" type="text" id="imap_authentication_mailbox" value="<?php echo htmlspecialchars($mailbox) ?>" size="80" /><br />eg: {mail.example.com/readonly}INBOX or {mail.example.com:993/ssl/novalidate-cert/readonly}INBOX</td>
		</tr>
		<tr valign="top">
		<th scope="row"><label for="imap_authentication_user_suffix">User Suffix</label></th>
		<td><input name="imap_authentication_user_suffix" type="text" id="imap_authentication_user_suffix" value="<?php echo htmlspecialchars($user_suffix) ?>" size="50" /><br />A suffix to add to usernames (typically used to automatically add the domain part of the login).<br />eg: <a class="h-card" href="http://twitter.com/example">@<span class="p-name p-nickname">example</span></a>.com</td>
		</tr>
		</table>
		</fieldset>
		<p class="submit">
		<input type="submit" name="Submit" value="<?php _e('Save Changes') ?>" />
		</p>
		</form>
		</div>
		<?php
}

if( !class_exists('IMAPAuthentication') ) {
	class IMAPAuthentication {
		/*
		 * Add an options pane for this plugin.
		 */
		function admin_menu() {
			add_options_page('IMAP Authentication', 'IMAP Authentication', 10, __FILE__);
		}

		/*
		 * Return the mailbox option from the database, creating the option if it doesn't exist.
		 */
		function get_mailbox() {
			global $cache_nonexistantoptions;

			$mailbox = get_settings('imap_authentication_mailbox');
			if (! $mailbox or $cache_nonexistantoptions['imap_authentication_mailbox']) {
				$mailbox = '{localhost:143}INBOX';
				IMAPAuthentication::add_mailbox_option($mailbox);
			}

			return $mailbox;
		}

		/*
		 * Add the mailbox option to the database.
		 */
		function add_mailbox_option($mailbox) {
			add_option('imap_authentication_mailbox', $mailbox, 'The mailbox to try and log into.');
		}

		/*
		 * Return the user_suffix option from the database, creating the option if it doesn't exist.
		 */
		function get_user_suffix() {
			global $cache_nonexistantoptions;

			$user_suffix = get_settings('imap_authentication_user_suffix');
			if (! $user_suffix or $cache_nonexistantoptions['imap_authentication_user_suffix']) {
				$user_suffix = '';
				IMAPAuthentication::add_user_suffix_option($user_suffix);
			}

			return $user_suffix;
		}

		/*
		 * Add the user_suffix option to the database.
		 */
		function add_user_suffix_option($user_suffix) {
			add_option('imap_authentication_user_suffix', $user_suffix, 'A suffix to add to usernames (typically used to automatically add the domain part of the login).');
		}

		function imap_authenticate($username, $password) {
			$mbox = @imap_open(IMAPAuthentication::get_mailbox(), $username.IMAPAuthentication::get_user_suffix(), $password, OP_HALFOPEN|OP_READONLY) or $error = imap_last_error();
			if ($mbox) {
				$userInfo = get_userdatabylogin($username);
				imap_close($mbox);
				return array(true, $userInfo);
			}
			return array(false,null);
		}

		// create or update the user in the local DB ...
		function update_wp_user($username, $password, $userinfo=null) {

			$user = get_userdatabylogin($username);
			$userid = ( is_object($user) && (int)$user->ID > 0 ) ? (int)$user->ID : 0;

			// if we have a user dont't ever try to overwrite wordpress data
			if ( $userid > 0 )
				return true;

			// Don't have enough data to create a new user
			return false;
		}

		function authenticate($user=null, $username='', $password='') {
			if ( is_a($user, 'WP_User') ) { return $user; }

			// check arguments to this function ...
			if ( empty($username) || empty($password) ) {
				$error = new WP_Error();
				if ( empty($username) ) $error->add('empty_username', __('<strong>ERROR</strong>: Missing username value.'));
				if ( empty($password) ) $error->add('empty_password', __('<strong>ERROR</strong>: Missing password value.'));
				return $error;
			}

			// validate the password
			{
				list($auth_result,$info) = IMAPAuthentication::imap_authenticate($username, $password);
				if ( $auth_result != true ) {
					if ( is_a($auth_result, 'WP_Error')) {
						return $auth_result;
					} else {
						return new WP_Error('invalid_username', __('<strong>Login Error</strong>: Could not authenticate your credentials.'));
					}
				}
			}
			// create a WP DB record for this user ...
			if ( ! IMAPAuthentication::update_wp_user($username, $password, $info) ) {
				return new WP_Error('invalid_username', __('<strong>Login Error</strong>: Could not authenticate your credentials.'));
			}

			return get_user_by('login', $username);
		}

		function check_password($unknown, $enteredPassword, $storedPassword, $userID) {
			$user = new WP_User($userID);
			return IMAPAuthentication::authenticate_user($user, $enteredPassword);
		}

		/*
		 * Used to disable certain login functions, e.g. retrieving a
		 * user's password.
		 */
		function disable_password() {
			login_header('Login', '<p class="message"><strong>ERROR</strong>: You can\'t do that here. This blog uses the IMAP login mechanism. Your password is set with your email account.</p>', 'error');
			die();
		}

		/*
		 * Used to disable certain display elements, e.g. password
		 * fields on profile screen.
		 */
		function show_password_fields($username) {
			return false;
		}
	}
}
?>
