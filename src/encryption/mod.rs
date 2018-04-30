pub mod asymm;
pub mod symm;

use failure::Error;

pub trait Encryptor {
	// Consume self because it might include a nonce
	fn encrypt(self, data: &[u8]) -> Result<Vec<u8>, Error>;
}
