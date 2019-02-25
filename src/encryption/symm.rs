use std::io::{self, Read, Write};

use failure::Error;

use miscreant::stream::{Aes256SivDecryptor, Aes256SivEncryptor};

use crate::header::encryption::Aes256Siv;

pub const TAG_SIZE: usize = 16;
pub const MESSAGE_SIZE: usize = 8 * 1024 - TAG_SIZE;

trait ChunkReader {
	fn read_chunk(&mut self, _: &mut [u8]) -> io::Result<usize>;
}

impl<T> ChunkReader for T
where
	T: Read,
{
	fn read_chunk(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
		let mut read = 0;

		while !buf.is_empty() {
			match self.read(buf) {
				Ok(0) => break,
				Ok(n) => {
					let tmp = buf;

					read += n;
					buf = &mut tmp[n..];
				}
				Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
				Err(e) => return Err(e),
			}
		}

		Ok(read)
	}
}

pub fn encrypt_stream<I, O>(
	key: &Aes256Siv,
	input: &mut I,
	output: &mut O,
	message_size: usize,
) -> Result<(), Error>
where
	I: Read,
	O: Write,
{
	let Aes256Siv { iv, key } = key;
	let mut encryptor = Aes256SivEncryptor::new(key, iv);
	let mut buf = vec![0; message_size + TAG_SIZE];
	let ad = [0; 0];

	loop {
		match input.read_chunk(&mut buf[TAG_SIZE..])? {
			n if n < message_size => {
				let mut buf = &mut buf[0..(TAG_SIZE + n)];

				encryptor.seal_last_in_place(&ad, &mut buf);
				output.write_all(buf)?;

				break;
			}
			_ => {
				encryptor.seal_next_in_place(&ad, &mut buf);
				output.write_all(&buf)?;
			}
		}
	}

	Ok(())
}

pub fn decrypt_stream<I, O>(
	key: &Aes256Siv,
	input: &mut I,
	output: &mut O,
	message_size: usize,
) -> Result<(), Error>
where
	I: Read,
	O: Write,
{
	let Aes256Siv { iv, key } = key;
	let mut decryptor = Aes256SivDecryptor::new(key, iv);
	let mut buf = vec![0; message_size + TAG_SIZE];
	let ad = [0; 0];

	loop {
		match input.read_chunk(&mut buf)? {
			n if n < buf.len() => {
				let buf = decryptor.open_last_in_place(&ad, &mut buf[0..n])?;

				output.write_all(buf)?;

				break;
			}
			_ => {
				let buf = decryptor.open_next_in_place(&ad, &mut buf)?;

				output.write_all(&buf)?;
			}
		}
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use std::cmp::min;
	use std::io::{self, Read, Write};

	use crate::encryption::symm::{
		decrypt_stream,
		encrypt_stream,
		Aes256Siv,
		MESSAGE_SIZE,
	};

	struct PartialReader<'a> {
		data: &'a [u8],
		cap: usize,
		pos: usize,
	}

	impl<'a> Read for PartialReader<'a> {
		fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
			let remaining = self.data.len() - self.pos;
			let read = min(min(remaining, buf.len()), self.cap);
			let data = &self.data[self.pos..(self.pos + read)];

			self.pos += read;

			buf.write(data)
		}
	}

	fn test_encrypt_decrypt(cleartext: &str, message_size: usize) {
		let key = Aes256Siv::new().unwrap();

		let mut input = cleartext.as_bytes();
		let mut encrypted = Vec::new();

		encrypt_stream(&key, &mut input, &mut encrypted, message_size).unwrap();

		let mut input = encrypted.as_slice();
		let mut decrypted = Vec::new();

		decrypt_stream(&key, &mut input, &mut decrypted, message_size).unwrap();

		let decrypted = String::from_utf8(decrypted).unwrap();

		assert!(cleartext == decrypted);
	}

	#[test]
	fn test_encrypt_stream_single_message() {
		test_encrypt_decrypt("Hello, World!", MESSAGE_SIZE);
	}

	#[test]
	fn test_encrypt_stream_multi_message() {
		test_encrypt_decrypt("Hello, World!", 4);
	}

	#[test]
	fn test_encrypt_stream_multi_message_exact() {
		test_encrypt_decrypt("Hello, World", 4);
	}

	#[test]
	fn test_encrypt_stream_partial_messages() {
		let key = Aes256Siv::new().unwrap();
		let cleartext = "Hello, World!";

		let mut input = PartialReader {
			data: cleartext.as_bytes(),
			cap: 3,
			pos: 0,
		};

		let mut encrypted = Vec::new();

		encrypt_stream(&key, &mut input, &mut encrypted, 8).unwrap();

		let mut input = encrypted.as_slice();
		let mut decrypted = Vec::new();

		decrypt_stream(&key, &mut input, &mut decrypted, 8).unwrap();

		let decrypted = String::from_utf8(decrypted).unwrap();

		assert!(cleartext == decrypted);
	}
}
