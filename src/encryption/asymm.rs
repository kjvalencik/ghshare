use failure::Error;
use openssh_keys::{self, PublicKey};
use openssl::bn::BigNum;
use openssl::rsa::{self, Rsa};
use rpassword;

use encryption::Encryptor;

impl Encryptor for PublicKey {
	fn encrypt(self, data: &[u8]) -> Result<Vec<u8>, Error> {
		match self.data {
			openssh_keys::Data::Rsa {
				exponent,
				modulus,
			} => {
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

pub fn decrypt_key(
	pem: &[u8],
	keys: &[Vec<u8>],
	prompt: bool,
) -> Result<Vec<u8>, Error> {
	let kek = Rsa::private_key_from_pem_callback(pem, |_| Ok(0));
	let kek = match kek {
		Ok(kek) => Ok(kek),
		Err(err) => {
			if prompt {
				let passphrase =
					rpassword::prompt_password_stderr("Passphrase: ")?;

				Rsa::private_key_from_pem_passphrase(pem, passphrase.as_bytes())
			} else {
				Err(err)
			}
		}
	}?;

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

	use encryption::Encryptor;
	use encryption::asymm::decrypt_key;

	#[test]
	fn test_encrypt_decrypt() {
		let private_key = include_bytes!("../../tests/keys/id_rsa");
		let public_key = include_str!("../../tests/keys/id_rsa.pub");

		let public_key = PublicKey::parse(public_key).unwrap();
		let cleartext = "Hello, World!";
		let ciphertext = public_key
			.encrypt(cleartext.as_bytes())
			.unwrap();
		let ciphertexts = vec![ciphertext];

		let key = decrypt_key(private_key, &ciphertexts, false).unwrap();
		let plaintext = String::from_utf8(key).unwrap();

		assert!(cleartext == plaintext);
	}
}
