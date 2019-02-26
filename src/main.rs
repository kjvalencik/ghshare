extern crate byteorder;
extern crate dirs;
extern crate env_logger;

#[macro_use]
extern crate failure;

#[macro_use]
extern crate log;
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

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use env_logger::Env;
use failure::Error;
use structopt::StructOpt;

use crate::cli::{CliInput, CliOutput, Opt};
use crate::encryption::asymm::{decrypt_data, decrypt_key};
use crate::encryption::symm::{decrypt_stream, encrypt_stream, MESSAGE_SIZE};
use crate::encryption::Encryptor;
use crate::header::encryption::{Aes256Siv, Key};
use crate::header::{Encryption, Header};

fn read_file<P>(file_name: P) -> Result<Vec<u8>, Error>
where
	P: AsRef<Path>,
{
	let mut file = File::open(file_name)?;
	let mut buf = Vec::new();

	file.read_to_end(&mut buf)?;

	Ok(buf)
}

fn run_encrypt_no_header(opt: cli::Encrypt) -> Result<(), Error> {
	let keys = github::get_public_keys(&opt)?;
	let mut data = Vec::new();
	let mut input = CliInput::new(opt.input)?;

	input.read_to_end(&mut data)?;

	let encrypted_data = keys
		.into_iter()
		.map(|key| -> Result<_, _> { key.to_public_key()?.encrypt(&data) })
		.filter_map(Result::ok)
		.last()
		.ok_or_else(|| format_err!("User does not have a supported key"))?;

	let mut output = CliOutput::new(opt.output)?;

	output.write_all(&encrypted_data)?;

	Ok(())
}

fn run_encrypt(opt: cli::Encrypt) -> Result<(), Error> {
	if opt.small {
		return run_encrypt_no_header(opt);
	}

	let key = Aes256Siv::new()?;
	let key_encoded = key.clone().encode()?;
	let encrypted_keys = github::get_public_keys(&opt)?
		.into_iter()
		.map(|key| -> Result<_, _> {
			let kek = key.to_public_key()?;

			kek.encrypt(&key_encoded)
		}).filter_map(Result::ok)
		.collect::<Vec<_>>();

	if encrypted_keys.is_empty() {
		bail!("User does not have a supported key");
	}

	let mut input = CliInput::new(opt.input)?;
	let mut output = CliOutput::new(opt.output)?;
	let header = (Header {
		encrypted_keys,
		chunk_size: MESSAGE_SIZE as u32,
	}).encode_length_delimited()?;

	output.write_all(&header)?;

	encrypt_stream(&key, &mut input, &mut output, MESSAGE_SIZE)?;

	Ok(())
}

fn read_private_key(key: &Option<String>) -> Result<Vec<u8>, Error> {
	let key_path = key.clone().map(PathBuf::from).or_else(|| {
		dirs::home_dir().map(|home_dir| home_dir.join(".ssh").join("id_rsa"))
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
	let private_key = read_private_key(&opt.key)?;

	if opt.small {
		let mut encrypted_data = Vec::new();

		input.read_to_end(&mut encrypted_data)?;

		let data =
			decrypt_data(&private_key, &encrypted_data, prompt_passphrase)?;

		output.write_all(&data)?;
	} else {
		let header = Header::decode_length_delimited(&mut input)?;
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
	let env = Env::default()
		.filter_or("GHSHARE_LOG_LEVEL", "warn")
		.write_style_or("GHSHARE_LOG_STYLE", "always");

	env_logger::init_from_env(env);

	// Load root certificates
	openssl_probe::init_ssl_cert_env_vars();

	info!("Parsing arguments");
	let opt = Opt::from_args();
	let mut stderr = std::io::stderr();

	if let Err(err) = run(opt) {
		for fail in err.iter_chain() {
			writeln!(stderr, "{}", fail).expect("Failed to write to stderr");
		}
	}
}
