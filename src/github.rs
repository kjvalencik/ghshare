use std::io::{self, Write};

use failure::{Error, ResultExt, SyncFailure};
use hyper::header::{Authorization, Basic};
use openssh_keys::PublicKey;
use reqwest::{self, RequestBuilder, Response, StatusCode};
use rpassword;

use crate::cli;

header! {
	(XGitHubOTP, "X-GitHub-OTP") => [String]
}

#[derive(Debug, Deserialize)]
pub struct GithubPublicKey {
	id: u64,
	key: String,
}

impl GithubPublicKey {
	pub fn to_public_key(&self) -> Result<PublicKey, Error> {
		let key = PublicKey::parse(&self.key)
			.map_err(SyncFailure::new)
			.context("Failed to parse key")?;

		Ok(key)
	}
}

fn prompt_stderr(prompt: &str) -> Result<String, Error> {
	eprint!("{}", prompt);
	io::stderr().flush()?;

	let mut res = String::new();

	io::stdin().read_line(&mut res)?;

	Ok(res.trim().to_owned())
}

fn is_otp_required(res: &Response) -> bool {
	if res.status() == StatusCode::Unauthorized {
		if let Some(header) = res.headers().get::<XGitHubOTP>() {
			header.starts_with("required")
		} else {
			false
		}
	} else {
		false
	}
}

// Wow. Reqwest doesn't support cloning request builders
// This exists as a builder to make similar requests multiple times.
struct GithubPublicKeyRequest {
	host: String,
	token: Option<Authorization<String>>,
	basic: Option<Authorization<Basic>>,
	otp: Option<XGitHubOTP>,
}

impl<'a> From<&'a cli::Encrypt> for GithubPublicKeyRequest {
	fn from(opt: &cli::Encrypt) -> GithubPublicKeyRequest {
		GithubPublicKeyRequest {
			host: format!("{}/users/{}/keys", opt.host, opt.recipient),
			otp: None,
			basic: None,
			token: None,
		}
	}
}

impl GithubPublicKeyRequest {
	fn set_token(&mut self, token: &str) {
		self.token = Some(Authorization(format!("token {}", token)));
	}

	fn prompt_credentials(&mut self) -> Result<(), Error> {
		let username = prompt_stderr("Username: ")?;
		let password = Some(rpassword::prompt_password_stderr("Password: ")?);

		self.basic = Some(Authorization(Basic { username, password }));

		Ok(())
	}

	fn prompt_otp(&mut self) -> Result<(), Error> {
		let otp = prompt_stderr("One Time Password: ")?;

		self.otp = Some(XGitHubOTP(otp));

		Ok(())
	}

	fn request(&self) -> RequestBuilder {
		let client = reqwest::Client::new();
		let mut req = client.get(&self.host);

		if let Some(ref token) = self.token {
			req.header(token.clone());
		}

		if let Some(ref basic) = self.basic {
			req.header(basic.clone());
		}

		if let Some(ref otp) = self.otp {
			req.header(otp.clone());
		}

		req
	}
}

pub fn get_public_keys(
	opt: &cli::Encrypt,
) -> Result<Vec<GithubPublicKey>, Error> {
	let mut req: GithubPublicKeyRequest = opt.into();

	// Always use token if we have one
	let mut res = if let Some(ref token) = opt.token {
		req.set_token(token);

		req.request().send()?
	} else {
		// Try without credentials
		let res = req.request().send()?;

		// If success or we can't prompt for credentials
		if res.status() == StatusCode::Ok || opt.input.is_none() {
			res

		// Prompt for credentials
		} else {
			req.prompt_credentials()?;

			let res = req.request().send()?;

			// Check if OTP was required
			if is_otp_required(&res) {
				req.prompt_otp()?;

				req.request().send()?
			} else {
				res
			}
		}
	};

	if res.status() != StatusCode::Ok {
		bail!("Failed to get public keys");
	}

	let keys = res.json::<Vec<GithubPublicKey>>()?;

	Ok(keys)
}
