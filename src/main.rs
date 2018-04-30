extern crate byteorder;

#[macro_use]
extern crate hyper;

#[macro_use]
extern crate failure;
extern crate miscreant;
extern crate openssh_keys;
extern crate openssl;
extern crate openssl_probe;
extern crate prost;

#[macro_use]
extern crate prost_derive;
extern crate reqwest;
extern crate rpassword;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

#[macro_use]
extern crate structopt;

mod cli;
mod encryption;
mod github;
mod header;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use failure::Error;
use structopt::StructOpt;

use cli::{CliInput, CliOutput, Opt};
use encryption::Encryptor;
use encryption::asymm::decrypt_key;
use encryption::symm::{decrypt_stream, encrypt_stream, MESSAGE_SIZE};
use header::encryption::{Aes256Siv, Key};
use header::{Encryption, Header};

fn read_file<P>(file_name: P) -> Result<Vec<u8>, Error>
where
	P: AsRef<Path>,
{
	let mut file = File::open(file_name)?;
	let mut buf = Vec::new();

	file.read_to_end(&mut buf)?;

	Ok(buf)
}

fn run_encrypt(opt: cli::Encrypt) -> Result<(), Error> {
	let key = Aes256Siv::new()?;
	let key_encoded = key.clone().encode()?;
	let encrypted_keys = github::get_public_keys(&opt)?
		.into_iter()
		.map(|key| -> Result<_, _> {
			let kek = key.to_public_key()?;

			kek.encrypt(&key_encoded)
		})
		.filter_map(|res| res.ok())
		.collect::<Vec<_>>();

	if encrypted_keys.len() <= 0 {
		bail!("User does not have a supported key");
	}

	let mut input = CliInput::new(opt.input)?;
	let mut output = CliOutput::new(opt.output)?;
	let header = (Header {
		encrypted_keys,
		chunk_size: MESSAGE_SIZE as u32,
	}).encode_length_delimited()?;

	output.write(&header)?;

	encrypt_stream(&key, &mut input, &mut output, MESSAGE_SIZE)?;

	Ok(())
}

fn read_private_key(key: &Option<String>) -> Result<Vec<u8>, Error> {
	let key_path = key.clone().map(PathBuf::from).or_else(|| {
		env::home_dir().map(|home_dir| home_dir.join(".ssh").join("id_rsa"))
	});

	match key_path {
		Some(key_path) => read_file(key_path),
		None => bail!("Could not find private key"),
	}
}

fn run_decrypt(opt: cli::Decrypt) -> Result<(), Error> {
	let prompt_passphrase = opt.input.is_some();
	let mut input = CliInput::new(opt.input)?;
	let mut output = CliOutput::new(opt.output)?;
	let header = Header::decode_length_delimited(&mut input)?;
	let private_key = read_private_key(&opt.key)?;
	let key = decrypt_key(
		&private_key,
		&header.encrypted_keys,
		prompt_passphrase,
	)?;

	let encryption = Encryption::decode(&key)?;

	match encryption.key {
		Some(Key::Aes256Siv(key)) => {
			decrypt_stream(
				&key,
				&mut input,
				&mut output,
				header.chunk_size as usize,
			)?;
		}
		_ => bail!("Could not find a usable key"),
	}

	Ok(())
}

fn run(opt: Opt) -> Result<(), Error> {
	match opt {
		Opt::Encrypt(opt) => run_encrypt(opt),
		Opt::Decrypt(opt) => run_decrypt(opt),
	}
}

fn main() {
	let opt = Opt::from_args();
	let mut stderr = std::io::stderr();

	// Load root certificates
	openssl_probe::init_ssl_cert_env_vars();

	if let Err(err) = run(opt) {
		for fail in err.causes() {
			writeln!(stderr, "{}", fail).expect("Failed to write to stderr");
		}
	}
}
