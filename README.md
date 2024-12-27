# Text encrypt/decrypt tool

This tool uses AES-128-CTR to encrypt your data and employs scrypt to derive the encryption key from your password. It is very simple to use: simply provide the file to be encrypted, specify the output filename, and enter your password. The output file contains the encrypted data in JSON format.

# Examples

Run `textenc --help` to get help information.

## Encrypt

Following the steps to encrypt your file.

1. Run `textenc encrypt --input-file ./hello.txt --output-file ./encrypted.json`

2. Enter the password

3. Done. The file `encrypted.json` will store the encrypted data with required parameters

## Decrypt

Following the steps to decrypt your file.

1. Run `textenc decrypt --input-file ./encrypted.json --output-file ./hello2.txt`

2. Enter the password

3. Done. The file `hello2.txt` will store the decrypted data

# How to compile?

* Install Rust

* Run `cargo build`

# How to test?

* Install Rust

* Run `cargo test`