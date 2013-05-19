<?php namespace Regulus\Recaptcha;

use Illuminate\Support\ServiceProvider;

use Illuminate\Support\Facades\Input;
use Illuminate\Support\Facades\Validator;

class RecaptchaServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot()
	{
		$this->package('regulus/recaptcha');

		//setup validation rule
		Validator::extend('recaptcha', function($attribute, $value, $parameters)
		{
			$resp = Recaptcha::checkAnswer(Input::get('recaptcha_challenge_field'), $value);
			if ($resp->isValid) return true;
			return false;
		});
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
		//
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array();
	}

}