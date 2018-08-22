use std::fs::File;
use std::io::{self, Read, Stdin, Stdout, Write};

#[derive(StructOpt, Debug)]
pub struct Decrypt {
	#[structopt(long = "key", short = "k")]
	pub key: Option<String>,

	#[structopt(long = "input", short = "i")]
	pub input: Option<String>,

	#[structopt(long = "output", short = "o")]
	pub output: Option<String>,
}

#[derive(StructOpt, Debug)]
pub struct Encrypt {
	#[structopt(
		long = "host",
		short = "h",
		default_value = "https://api.github.com"
	)]
	pub host: String,

	#[structopt(long = "recipient", short = "r")]
	pub recipient: String,

	#[structopt(long = "token", short = "a", help = "perosnal access token")]
	pub token: Option<String>,

	#[structopt(long = "input", short = "i")]
	pub input: Option<String>,

	#[structopt(long = "output", short = "o")]
	pub output: Option<String>,
}

#[derive(StructOpt, Debug)]
#[structopt(name = "ghshare")]
pub enum Opt {
	#[structopt(name = "decrypt")]
	Decrypt(Decrypt),

	#[structopt(name = "encrypt")]
	Encrypt(Encrypt),
}

pub enum CliInput {
	File(File),
	Stdin(Stdin),
}

impl Read for CliInput {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		match self {
			CliInput::File(file) => file.read(buf),
			CliInput::Stdin(stdin) => stdin.read(buf),
		}
	}
}

impl CliInput {
	pub fn new(input: Option<String>) -> io::Result<CliInput> {
		if let Some(file) = input {
			Ok(CliInput::File(File::open(&file)?))
		} else {
			Ok(CliInput::Stdin(io::stdin()))
		}
	}
}

pub enum CliOutput {
	File(File),
	Stdout(Stdout),
}

impl Write for CliOutput {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		match self {
			CliOutput::File(file) => file.write(buf),
			CliOutput::Stdout(stdout) => stdout.write(buf),
		}
	}

	fn flush(&mut self) -> io::Result<()> {
		match self {
			CliOutput::File(file) => file.flush(),
			CliOutput::Stdout(stdout) => stdout.flush(),
		}
	}
}

impl CliOutput {
	pub fn new(output: Option<String>) -> io::Result<CliOutput> {
		if let Some(file) = output {
			Ok(CliOutput::File(File::create(&file)?))
		} else {
			Ok(CliOutput::Stdout(io::stdout()))
		}
	}
}
