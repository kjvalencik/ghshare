use prost_build;

fn main() {
	prost_build::compile_protos(&["src/header.proto"], &["src/"])
		.expect("Failed to compile header.proto");
}
