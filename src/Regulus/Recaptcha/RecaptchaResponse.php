<?php namespace Regulus\Recaptcha;

/**
 * A ReCaptchaResponse is returned from recaptchaCheckAnswer()
 */
class ReCaptchaResponse {
	var $isValid;
	var $error;
}