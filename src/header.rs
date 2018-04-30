include!(concat!(env!("OUT_DIR"), "/ghshare.rs"));

use std::io::Read;

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};
use failure::Error;
use openssl::rand;
use prost::Message;

use self::encryption::{Aes256Siv, Key};

impl Aes256Siv {
	pub fn new() -> Result<Aes256Siv, Error> {
		let mut iv = vec![0; 8];
		let mut key = vec![0; 64];

		rand::rand_bytes(&mut iv)?;
		rand::rand_bytes(&mut key)?;

		Ok(Aes256Siv { iv, key })
	}

	pub fn encode(self) -> Result<Vec<u8>, Error> {
		let mut buf = Vec::new();
		let encryption = Encryption {
			key: Some(Key::Aes256Siv(self)),
		};

		encryption.encode(&mut buf)?;

		Ok(buf)
	}
}

impl Encryption {
	pub fn decode(input: &[u8]) -> Result<Encryption, Error> {
		let encryption = Message::decode(input)?;

		Ok(encryption)
	}
}

impl Header {
	pub fn encode(&self) -> Result<Vec<u8>, Error> {
		let mut buf = Vec::new();

		Message::encode(self, &mut buf)?;

		Ok(buf)
	}

	// Uses a fixed length size to simplify reading from from a `Read` instead
	// of a buffer.
	pub fn encode_length_delimited(&self) -> Result<Vec<u8>, Error> {
		let encoded = self.encode()?;
		let mut buf = vec![0; 4];

		LittleEndian::write_u32(&mut buf, encoded.len() as u32);
		buf.extend(encoded);

		Ok(buf)
	}

	pub fn decode_length_delimited<T>(input: &mut T) -> Result<Header, Error>
	where
		T: Read,
	{
		let len = input.read_u32::<LittleEndian>()?;
		let mut header_buf = vec![0; len as usize];

		input.read_exact(&mut header_buf)?;

		let header = Header::decode(header_buf)?;

		Ok(header)
	}
}
