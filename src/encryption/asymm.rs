use failure::{bail, format_err, Error};
use openssh_keys::{self, PublicKey};
use openssl::bn::BigNum;
use openssl::pkey::Private;
use openssl::rsa::{self, Rsa};
use rpassword;
use thrussh_keys::decode_secret_key;
use thrussh_keys::key::KeyPair;

use crate::encryption::Encryptor;

impl Encryptor for PublicKey {
	fn encrypt(self, data: &[u8]) -> Result<Vec<u8>, Error> {
		match self.data {
			openssh_keys::Data::Rsa { exponent, modulus } => {
				let exponent = BigNum::from_slice(&exponent)?;
				let modulus = BigNum::from_slice(&modulus)?;
				let rsa = Rsa::from_public_components(modulus, exponent)?;

				let mut encrypted = vec![0; rsa.size() as usize];
				let len = rsa.public_encrypt(
					data,
					&mut encrypted,
					rsa::Padding::PKCS1,
				)?;

				if len <= data.len() {
					bail!("Failed to encrypt data");
				}

				Ok(encrypted)
			}
			_ => bail!("Unsupported public key type"),
		}
	}
}

fn decrypt_private_key(
	encoded_key: &str,
	prompt: bool,
) -> Result<Rsa<Private>, Error> {
	let key = decode_secret_key(encoded_key, None);
	let key = match key {
		Err(thrussh_keys::Error::KeyIsEncrypted) => {
			if prompt {
				let passphrase =
					rpassword::prompt_password_stderr("Passphrase: ")?;

				decode_secret_key(encoded_key, Some(passphrase.as_bytes()))
			} else {
				key
			}
		},
		key => key,
	};

	match key? {
		KeyPair::RSA { key, .. } => Ok(key),
		KeyPair::Ed25519(_) => bail!("Unsupported key type (Ed25519)"),
	}
}

pub fn decrypt_data(
	key: &str,
	data: &[u8],
	prompt: bool,
) -> Result<Vec<u8>, Error> {
	let key = decrypt_private_key(key, prompt)?;
	let mut buf = vec![0; key.size() as usize];
	let len = key.private_decrypt(&data, &mut buf, rsa::Padding::PKCS1)?;

	Ok(buf[..len].to_vec())
}

pub fn decrypt_key(
	key: &str,
	keys: &[Vec<u8>],
	prompt: bool,
) -> Result<Vec<u8>, Error> {
	let kek = decrypt_private_key(key, prompt)?;
	let mut last_error = format_err!("Could not find a key");
	let mut buf = vec![0; kek.size() as usize];

	for key in keys {
		match kek.private_decrypt(&key, &mut buf, rsa::Padding::PKCS1) {
			Ok(len) => return Ok(buf[..len].to_vec()),
			Err(err) => last_error = err.into(),
		}
	}

	Err(last_error)
}

#[cfg(test)]
mod tests {
	use openssh_keys::PublicKey;

	use crate::encryption::asymm::decrypt_key;
	use crate::encryption::Encryptor;

	#[test]
	fn test_encrypt_decrypt() {
		let private_key = include_str!("../../tests/keys/id_rsa");
		let public_key = include_str!("../../tests/keys/id_rsa.pub");

		let public_key = PublicKey::parse(public_key).unwrap();
		let cleartext = "Hello, World!";
		let ciphertext = public_key.encrypt(cleartext.as_bytes()).unwrap();
		let ciphertexts = vec![ciphertext];

		let key = decrypt_key(private_key, &ciphertexts, false).unwrap();
		let plaintext = String::from_utf8(key).unwrap();

		assert!(cleartext == plaintext);
	}
}
