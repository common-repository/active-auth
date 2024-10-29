<?php
/**
 * Plugin Name: Active Auth
 * Plugin URI: http://activeauth.me
 * Description: This plugin enables two-factor authentication for WordPress logins with mobile phone push over data, text messages, and even a phone call.
 * Version: 1.0
 * Author: ActiveScape
 * Author URI: http://activescape.net/
 * License: GPL2
 */

/*  Copyright 2014  ActiveAuth  (http://activeauth.me)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

require_once('includes/ActiveAuthSettings.php');
require_once('includes/ActiveAuth.php');

$ActiveAuthCookieName = 'aca_auth_cookie';
$ActiveSecAuthCookieName = 'aca_secure_auth_cookie';

function sign_request($user, $redirect=null)
{

    if ($redirect) {
        return null;
    }

    $options = get_option('aca-options');

    $username = $user->user_email;
    $server = 'activeauth.me';
    $ikey = $options['aca_ikey'];
    $iaccount = $options['aca_iaccount'];
    $skey = $options['aca_skey'];
    $akey = get_option('aca_akey');

    $aca = new ActiveAuth();
    $secret = $aca->sign($username, $ikey, $skey, $akey);

?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Active Auth</title>
        <meta charset="utf-8" />
        <meta name="HandheldFriendly" content="true"/>
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=2, user-scalable=yes"/>
        <?= '<link rel="stylesheet" type="text/css" href="' . admin_url('css/login.min.css') . '" />' ?>
        <style>
            body {
                background: #f1f1f1;
            }
            header {
                width: 100%;
                padding-top: 8%;
                margin-bottom: 2%;
            }
            h2 {
                text-align: center;
                color: #0074A2;
            }
            #acaframe {
                width: 90%;
                height: 350px;
                max-width: 600px;
                display: table;
                margin: 0 auto;
                border: 0;
            }
        </style>
    </head>
    <body>
        <div class="wrapper">
            <header>
                <div class="login">
                    <h1><a href="https://wordpress.org/" title="Powered by WordPress">ActiveAuth</a></h1>
                    <h2>ActiveAuth</h2>
                </div>
            </header>
            <section>
                <iframe src="" id="acaframe">
                </iframe>
                <script type="text/javascript">
                    var ACASecret = '<?= $secret ?>';
                    var ACAServer = '<?= $server ?>';
                    var ACAAccount = '<?= $iaccount ?>';
                    var ACAAction = '';
                </script>
                <script type="text/javascript" src="<?= plugins_url('js/aca.js', __FILE__) ?>"></script>
            </section>
            <div class="push"></div>
        </div>
        <footer>
        </footer>
    </body>
    </html>
<?php
}

function authenticate_user($user='', $username='', $password='')
{
    if (is_a($user, 'WP_User')) {
       return $user;
    }

    if (!aca_enabled()){
        return null;
    }

    if (isset($_POST['2fa-verify'])) {
        $options = get_option('aca-options');
        $skey = $options['aca_skey'];
        $akey = get_option('aca_akey');

        $aca = new ActiveAuth();

        $response = $_POST['2fa-verify'];
        $status = $aca->verify($response, $skey, $akey);
        if ($status) {
            remove_action('authenticate', 'wp_authenticate_username_password', 20);
            $user = get_user_by('email', $status);
            $user = new WP_User(0, $user->user_login);
            aca_set_cookie($user);
            return $user;
        } else {
            $user = new WP_Error('Authentication failed', 'Failed or expired two factor authentication');
            return $user;
        }
    }

    $user = new WP_User(0, $username);
    if (!$user) {
        return null;
    }

    if(!aca_user_role($username)){
        return null;
    }

    remove_action('authenticate', 'wp_authenticate_username_password', 20);
    $user = wp_authenticate_username_password(NULL, $username, $password);

    if (!is_a($user, 'WP_User')) {
        return $user;
    } else {
        sign_request($user);
        exit();
    }

}

function aca_enabled()
{
    $options = get_option('aca-options');
    if ($options['aca_enabled'] == 1) {
        if ($options['aca_ikey'] != '' && $options['aca_skey'] != '' && $options['aca_iaccount'] != '') {
            return true;
        }
    }
    return false;
}

function aca_set_cookie($user)
{
    global $ActiveAuthCookieName;
    global $ActiveSecAuthCookieName;
    $options = get_option('aca-options');
    $ikey_b64 = base64_encode($options['aca_ikey']);
    $username_b64 = base64_encode($user->user_login);
    $expire = strtotime('+48 hours');
    //Create http cookie
    $val = base64_encode(sprintf("%s|%s|%s|%s", $ActiveAuthCookieName, $username_b64, $ikey_b64, $expire));
    $sig = aca_hash_hmac($val);
    $cookie = sprintf("%s|%s", $val, $sig);
    setcookie($ActiveAuthCookieName, $cookie, 0, COOKIEPATH, COOKIE_DOMAIN, false, true);
    if (COOKIEPATH != SITECOOKIEPATH){
        setcookie($ActiveAuthCookieName, $cookie, 0, SITECOOKIEPATH, COOKIE_DOMAIN, false, true);
    }

    if (is_ssl()){
        //Create https cookie
        $sec_val = base64_encode(sprintf("%s|%s|%s|%s", $ActiveSecAuthCookieName, $username_b64, $ikey_b64, $expire));
        $sec_sig = aca_hash_hmac($sec_val);
        $sec_cookie = sprintf("%s|%s", $sec_val, $sec_sig);
        setcookie($ActiveSecAuthCookieName, $sec_cookie, 0, COOKIEPATH, COOKIE_DOMAIN, true, true);
        if (COOKIEPATH != SITECOOKIEPATH){
            setcookie($ActiveSecAuthCookieName, $sec_cookie, 0, SITECOOKIEPATH, COOKIE_DOMAIN, true, true);
        }
    }

}

function aca_verify_auth()
{
    if(!aca_enabled()){
        return null;
    }

    if(is_user_logged_in()){
        $user = wp_get_current_user();
        if (!aca_verify_cookie($user) && aca_user_role($user->user_login)){
			if (aca_uri_request()) {
				aca_set_cookie($user);
			} else {
				sign_request($user);
			}
        }
    }
}

function aca_uri_request()
{
    if (isset($_SERVER['REQUEST_URI']) || (empty($_SERVER['QUERY_STRING']) && strpos($_SERVER['REQUEST_URI'], '?', 0))) {
        if (strpos($_SERVER['QUERY_STRING'], 'aca-settings')) {
			return true;
        }
    }
}

function aca_unset_cookie(){
    global $ActiveAuthCookieName;
    global $ActiveSecAuthCookieName;
    setcookie($ActiveAuthCookieName, '', strtotime('-1 day'), COOKIEPATH, COOKIE_DOMAIN);
    setcookie($ActiveAuthCookieName, '', strtotime('-1 day'), SITECOOKIEPATH, COOKIE_DOMAIN);
    setcookie($ActiveSecAuthCookieName, '', strtotime('-1 day'), COOKIEPATH, COOKIE_DOMAIN);
    setcookie($ActiveSecAuthCookieName, '', strtotime('-1 day'), SITECOOKIEPATH, COOKIE_DOMAIN);
}

function aca_verify_cookie($user)
{
    global $ActiveAuthCookieName;
    global $ActiveSecAuthCookieName;

    if (is_ssl() || isset($_COOKIE[$ActiveSecAuthCookieName])){
        $duo_auth_cookie_name = $ActiveSecAuthCookieName;
    }
    else {
        $duo_auth_cookie_name = $ActiveAuthCookieName;
    }

    if(!isset($_COOKIE[$duo_auth_cookie_name])){
        return false;
    }

    $cookie_list = explode('|', $_COOKIE[$duo_auth_cookie_name]);
    if (count($cookie_list) !== 2){
        return false;
    }
    list($u_cookie_b64, $u_sig) = $cookie_list;
    if (!aca_verify_sig($u_cookie_b64, $u_sig)){
        return false;
    }

    $cookie_content = explode('|', base64_decode($u_cookie_b64));
    if (count($cookie_content) !== 4){
        return false;
    }
    list($cookie_name, $cookie_username_b64, $cookie_ikey_b64, $expire) = $cookie_content;
    $options = get_option('aca-options', '');
    if ($cookie_name !== $duo_auth_cookie_name ||
        base64_decode($cookie_username_b64) !== $user->user_login ||
        base64_decode($cookie_ikey_b64) !== $options['aca_ikey']){

        return false;
    }

    $expire = intval($expire);
    if ($expire < strtotime('now')){
        return false;
    }
    return true;
}

function aca_verify_sig($cookie, $u_sig){
    $sig = aca_hash_hmac($cookie);
    if (aca_hash_hmac($sig) === aca_hash_hmac($u_sig)) {
        return true;
    }
    return false;
}

function aca_hash_hmac($data)
{
    return hash_hmac('sha1', $data, get_option('aca_akey', ''));
}

function aca_user_role($username)
{
    $wp_roles = aca_get_roles();
    $user = new WP_User(0, $username);

    $all_roles = array();
    foreach ($wp_roles->get_names() as $k=>$r) {
        $all_roles[$k] = $r;
    }

    $aca_roles = get_option('aca_roles', $all_roles);

    if(empty($user->roles)) {
        return true;
    }

    foreach ($user->roles as $role) {
        if (array_key_exists($role, $aca_roles)) {
            return true;
        }
    }
    return false;
}

function get_random_key($length=14)
{
    $chars = array(
        'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'r', 's',
        't', 'u', 'v', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L',
        'M', 'N', 'O', 'P', 'R', 'S',
        'T', 'U', 'V', 'X', 'Y', 'Z',
        '1', '2', '3', '4', '5', '6',
        '7', '8', '9', '0'
    );

    $char_count = count($chars);
    $key = '';

    for($i=0; $i<$length; $i++){
        $index = mt_rand(0, $char_count);
        shuffle($chars);
        $key .= $chars[$index];
    }

    $key = $key.md5(time());

    return str_shuffle($key);
}

function aca_get_roles()
{
    global $wp_roles;
    $wp_roles = isset($wp_roles) ? $wp_roles : new WP_Roles();
    return $wp_roles;
}

add_action('init', 'aca_verify_auth', 10);
add_action('clear_auth_cookie', 'aca_unset_cookie', 10);
add_filter('authenticate', 'authenticate_user', 10, 3);

if(is_admin()) {
    $my_settings_page = new ActiveAuthSettings(plugin_basename(__FILE__));
}

function aca_activation()
{
    if(!get_option('aca_akey')){
        add_option('aca_akey', get_random_key());
    }
}

register_activation_hook( __FILE__, 'aca_activation' );


function aca_deactivation()
{
    if(get_option('aca_akey')){
        delete_option('aca_akey');
    }

    if(get_option('aca_roles')){
        delete_option('aca_roles');
    }

    if(get_option('aca-options')){
        delete_option('aca-options');
    }
}

register_deactivation_hook( __FILE__, 'aca_deactivation' );