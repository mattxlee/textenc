# Text encrypt/decrypt tool

This tool uses AES-128-CTR to encrypt your data and employs scrypt to derive the encryption key from your password. It is very simple to use: simply provide the file to be encrypted, specify the output filename, and enter your password. The output file contains the encrypted data in JSON format.

# How to compile?

* Install Rust

* Run `cargo build`

# How to test?

* Install Rust

* Run `cargo test`