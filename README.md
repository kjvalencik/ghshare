# ghshare

Encrypt data at rest using a user's public key on github.  

Sometimes you want to share something encrypted and the recipient hasn't created a PGP key, but, they've uploaded a public key to GitHub. `ghshare` can fetch those keys and use them to encrypt a file.  

## Installation

### Download binary

Download a [binary release](https://github.com/kjvalencik/ghshare/releases)  
You will need to take the normal actions your platform requires to run a binary downloaded from the internet (macOS example: Enable macOS run unsigned binary, Make binary executable, Add binary to PATH, etc...)  

## Usage

```sh
ghshare command [flags] [options]
```

Available commands:  

### encrypt

Basic form of encryption command:  

```
ghshare encrypt --input <plaintextFileName> --output <ciphertextFileName> --recipient <receiversGithubUsername>
```

> :information_source: Each of the receiver's GitHub public keys (available here: https://api.github.com/users/receiversGithubUsername/keys) will be used to encrypt the input file.
> The receiver will only need to possess and use one of their corresponding private keys to decrypt the data.

#### flags

 flag                        | purpose
-----------------------------|---------
`--help`                     | Prints help information
`--small`, `-s`              | Encrypt without header for small data, OpenSSL compatible
`--version`, `-V`            | Prints version information

#### options

 flag               | param        | default                | required | purpose
--------------------|--------------|------------------------|----------|---------
`--host`, `-h`      | `<host>`     | https://api.github.com | `false`  | Endpoint to query for recipient's public keys
`--input`, `-i`     | `<path>`     |                        | `true`   | Path to file to be encrypted
`--output`, `-o`    | `<path>`     |                        | `true`   | File path to write encrypted data to
`--recipient`, `-r` | `<username>` |                        | `true`   | GitHub username of the encrypted data recipient
`--token`, `-a`     | `<token>`    |                        | `false`  | Manually provide GitHub access token

### decrypt

Basic form of decryption command:  

```
ghshare decrypt --input <ciphertextFileName> --output <plaintextFileName> --key <personalGithubPrivateKeyFile>
```

> :construction: At the moment **Only RSA keypairs supported** (see TODO)

#### flags

 flag                        | purpose
-----------------------------|---------
`--help`                     | Prints help information
`--small`, `-s`              | Decrypt small data without a header, OpenSSL alternative
`--version`, `-V`            | Prints version information

#### options

 flag            | param    | required | purpose
-----------------|----------|----------|---------
`--input`, `-i`  | `<path>` | `true`   | Path to file to be decrypted
`--key`, `-k`    | `<path>` | `true`   | Path to private key file used for decryption
`--output`, `-o` | `<path>` | `true`   | File path to write decrypted data to

## How It Works

### Encryption

1. `ghshare` fetches all of a recipient's public keys, prompting for
	credentials if necessary
1. A random symmetric key is generated
1. The symmetric key is encrypted with each of the user's public keys
1. The file is encrypted with [AES-256-SIV][miscreant].

### Decryption

1. `ghshare` reads a header from the file contained encrypted keys
1. `ghshare` uses the private key to attempt to decrypt keys until it finds a
	match.
1. Decrypts the data

## Using With GitHub Enterprise

If your instance of GitHub Enterprise does not have a dedicated API host, you
will need to suffix the host with `/api/v3`.

```sh
ghshare encrypt -h https://example.com/api/v3 ...
```

## TODO

* [x] Documentation
* [ ] Handle different public key types
	- [x] RSA
	- [ ] DSA
	- [ ] Ed25519
	- [ ] Ecdsa
* [ ] Error messaging
* [ ] Better key matching

[miscreant]: https://github.com/miscreant/miscreant
