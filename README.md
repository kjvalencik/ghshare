# ghshare

> Encrypt data at rest using a user's public key on github.

## Usage

```sh
ghshare -h
```

### GitHub Enterprise

If your instance of GitHub Enterprise does not have a dedicated API host, you
will need to suffix the host with `/api/v3`.

```sh
ghshare encrypt -h https://example.com/api/v3 ...
```

## How

Sometimes you want to share something encrypted and the recipient hasn't created
a PGP key, but, they've uploaded a public key to GitHub. `ghshare` can fetch
those keys and use them to encrypt a file.

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

## TODO

* [ ] Documentation
* [ ] Handle different public key types
	- [x] RSA
	- [ ] DSA
	- [ ] Ed25519
	- [ ] Ecdsa
* [ ] Error messaging
* [ ] Better key matching

[miscreant]: https://github.com/miscreant/miscreant
