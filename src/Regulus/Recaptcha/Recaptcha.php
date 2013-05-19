<?php namespace Regulus\Recaptcha;

/*----------------------------------------------------------------------------------------------------------
	ReCaptcha adapted for Laravel 4
		A version of the ReCaptcha class adapted for Laravel 4.

		created by Cody Jassman (based on the work of Mike Crawford and Be Maurer, info and license below)
		last updated on May 18, 2013
----------------------------------------------------------------------------------------------------------*/

/*
 * This is a PHP library that handles calling reCAPTCHA.
 *    - Documentation and latest version
 *          http://recaptcha.net/plugins/php/
 *    - Get a reCAPTCHA API Key
 *          https://www.google.com/recaptcha/admin/create
 *    - Discussion group
 *          http://groups.google.com/group/recaptcha
 *
 * Copyright (c) 2007 reCAPTCHA -- http://recaptcha.net
 * AUTHORS:
 *   Mike Crawford
 *   Ben Maurer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

use Illuminate\Support\Facades\Config;

/**
 * The reCAPTCHA server URLs
 */
define("RECAPTCHA_API_SERVER", "http://www.google.com/recaptcha/api");
define("RECAPTCHA_API_SECURE_SERVER", "https://www.google.com/recaptcha/api");
define("RECAPTCHA_VERIFY_SERVER", "www.google.com");

class Recaptcha {

	/**
	 * Encodes the given data into a query string format
	 * @param $data - array of string elements to be encoded
	 * @return string - encoded request
	 */
	protected static function _recaptchaQsencode($data)
	{
			$req = "";
			foreach ( $data as $key => $value )
					$req .= $key . '=' . urlencode( stripslashes($value) ) . '&';

			// Cut the last '&'
			$req=substr($req,0,strlen($req)-1);
			return $req;
	}

	/**
	 * Submits an HTTP POST to a reCAPTCHA server
	 * @param string $host
	 * @param string $path
	 * @param array $data
	 * @param int port
	 * @return array response
	 */
	protected static function _recaptchaHttpPost($host, $path, $data, $port = 80)
	{

			$req = static::_recaptchaQsencode ($data);

			$httpRequest  = "POST $path HTTP/1.0\r\n";
			$httpRequest .= "Host: $host\r\n";
			$httpRequest .= "Content-Type: application/x-www-form-urlencoded;\r\n";
			$httpRequest .= "Content-Length: " . strlen($req) . "\r\n";
			$httpRequest .= "User-Agent: reCAPTCHA/PHP\r\n";
			$httpRequest .= "\r\n";
			$httpRequest .= $req;

			$response = '';
			if( false == ( $fs = @fsockopen($host, $port, $errno, $errstr, 10) ) ) {
					die ('Could not open socket');
			}

			fwrite($fs, $httpRequest);

			while (!feof($fs))
					$response .= fgets($fs, 1160); // One TCP-IP packet
			fclose($fs);
			$response = explode("\r\n\r\n", $response, 2);

			return $response;
	}

	/**
	 * Gets the challenge HTML (javascript and non-javascript version).
	 * This is called from the browser, and the resulting reCAPTCHA HTML widget
	 * is embedded within the HTML form it was called from.
	 * @param string $pubkey A public key for reCAPTCHA
	 * @param string $error The error given by reCAPTCHA (optional, default is null)
	 * @param boolean $useSSL Should the request be made over ssl? (optional, default is false)
	 * @return string - The HTML to be embedded in the user's form.
	 */
	public static function getHTML($error = null, $useSSL = false)
	{
		$pubkey = Config::get('recaptcha::publicKey');
		if ($pubkey == null || $pubkey == '') {
			die ("To use reCAPTCHA you must get an API key from <a href='https://www.google.com/recaptcha/admin/create'>https://www.google.com/recaptcha/admin/create</a>");
		}

		if ($useSSL) {
		$server = RECAPTCHA_API_SECURE_SERVER;
		} else {
		$server = RECAPTCHA_API_SERVER;
		}

		$errorPart = "";
		if ($error) {
		   $errorPart = "&amp;error=" . $error;
		}
		return '<div class="recaptcha"><script type="text/javascript" src="'. $server . '/challenge?k=' . $pubkey . $errorPart . '"></script>
		<noscript>
			<iframe src="'. $server . '/noscript?k=' . $pubkey . $errorPart . '" height="300" width="500" frameborder="0"></iframe><br/>
			<textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
			<input type="hidden" name="recaptcha_response_field" value="manual_challenge"/>
		</noscript></div>';
	}

	/**
	  * Calls an HTTP POST function to verify if the user's guess was correct
	  * @param string $remoteip
	  * @param string $challenge
	  * @param string $response
	  * @param array $extraParams an array of extra variables to post to the server
	  * @return ReCaptchaResponse
	  */
	public static function checkAnswer($challenge, $response, $extraParams = array())
	{
		$remoteip = $_SERVER['REMOTE_ADDR'];

		$privkey = Config::get('recaptcha::privateKey');
		if ($privkey == null || $privkey == '') {
			die ("To use reCAPTCHA you must get an API key from <a href='https://www.google.com/recaptcha/admin/create'>https://www.google.com/recaptcha/admin/create</a>");
		}

		if ($remoteip == null || $remoteip == '') {
			die ("For security reasons, you must pass the remote ip to reCAPTCHA");
		}

		//discard spam submissions
		if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0) {
				$recaptchaResponse = new RecaptchaResponse();
				$recaptchaResponse->isValid = false;
				$recaptchaResponse->error = 'incorrect-captcha-sol';
				return $recaptchaResponse;
		}

		$response = static::_recaptchaHttpPost(RECAPTCHA_VERIFY_SERVER, "/recaptcha/api/verify",
			array (
				'privatekey' => $privkey,
				'remoteip' => $remoteip,
				'challenge' => $challenge,
				'response' => $response,
			) + $extraParams
		);

		$answers           = explode("\n", $response[1]);
		$recaptchaResponse = new RecaptchaResponse();

		if (trim($answers[0]) == 'true') {
				$recaptchaResponse->isValid = true;
		} else {
			$recaptchaResponse->isValid = false;
			$recaptchaResponse->error = $answers[1];
		}
		return $recaptchaResponse;
	}

	/**
	 * gets a URL where the user can sign up for reCAPTCHA. If your application
	 * has a configuration page where you enter a key, you should provide a link
	 * using this function.
	 * @param string $domain The domain where the page is hosted
	 * @param string $appname The name of your application
	 */
	public static function recaptchaGetSignupURL($domain = null, $appname = null)
	{
		return "https://www.google.com/recaptcha/admin/create?" .  static::_recaptchaQsencode (array ('domains' => $domain, 'app' => $appname));
	}

	protected static function _recaptchaAesPad($val)
	{
		$blockSize = 16;
		$numpad = $blockSize - (strlen ($val) % $blockSize);
		return str_pad($val, strlen ($val) + $numpad, chr($numpad));
	}

	/* Mailhide related code */
	protected static function _recaptchaAesEncrypt($val, $ky)
	{
		if (!function_exists ("mcrypt_encrypt")) {
			die ("To use reCAPTCHA Mailhide, you need to have the mcrypt php module installed.");
		}
		$mode = MCRYPT_MODE_CBC;
		$enc  = MCRYPT_RIJNDAEL_128;
		$val  = static::_recaptchaAesPad($val);
		return mcrypt_encrypt($enc, $ky, $val, $mode, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
	}


	protected static function _recaptchaMailhideUrlBase64($x)
	{
		return strtr(base64_encode($x), '+/', '-_');
	}

	/* gets the reCAPTCHA Mailhide url for a given email, public key and private key */
	protected static function recaptchaMailhideURL($email)
	{
		$pubkey  = Config::get('recaptcha::publicKey');
		$privkey = Config::get('recaptcha::privateKey');
		if ($pubkey == '' || $pubkey == null || $privkey == "" || $privkey == null) {
			die ("To use reCAPTCHA Mailhide, you have to sign up for a public and private key, " .
				 "you can do so at <a href='http://www.google.com/recaptcha/mailhide/apikey'>http://www.google.com/recaptcha/mailhide/apikey</a>");
		}

		$ky = pack('H*', $privkey);
		$cryptmail =static::_recaptchaAesEncrypt($email, $ky);

		return "http://www.google.com/recaptcha/mailhide/d?k=" . $pubkey . "&c=" . static::_recaptchaMailhideUrlBase64($cryptmail);
	}

	/**
	 * gets the parts of the email to expose to the user.
	 * eg, given johndoe@example,com return ["john", "example.com"].
	 * the email is then displayed as john...@example.com
	 */
	protected static function _recaptchaMailhideEmailParts($email)
	{
		$arr = preg_split("/@/", $email);

		if (strlen($arr[0]) <= 4) {
			$arr[0] = substr($arr[0], 0, 1);
		} else if (strlen ($arr[0]) <= 6) {
			$arr[0] = substr($arr[0], 0, 3);
		} else {
			$arr[0] = substr($arr[0], 0, 4);
		}
		return $arr;
	}

	/**
	 * Gets html to display an email address given a public an private key.
	 * to get a key, go to:
	 *
	 * http://www.google.com/recaptcha/mailhide/apikey
	 */
	protected static function recaptchaMailhideHTML($email)
	{
		$pubkey     = Config::get('recaptcha::publicKey');
		$privkey    = Config::get('recaptcha::privateKey');
		$emailParts = static::_recaptchaMailhideEmailParts($email);
		$url        = static::recaptchaMailhideURL($pubkey, $privkey, $email);

		return htmlentities($emailParts[0]) . "<a href='" . htmlentities($url) .
			"' onclick=\"window.open('" . htmlentities ($url) . "', '', 'toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0,width=500,height=300'); return false;\" title=\"Reveal this e-mail address\">...</a>@" . htmlentities($emailParts[1]);

	}

}