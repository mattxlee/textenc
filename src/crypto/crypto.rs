use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes128,
};
use anyhow::{bail, Result};
use ctr::Ctr128BE;
use scrypt::{scrypt, Params};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::rand::rand_bytes;

type Aes128Ctr = Ctr128BE<Aes128>;

#[derive(Serialize, Deserialize)]
pub struct KdfParams {
    dklen: usize,
    salt: String,
    log_n: u8,
    n: u32,
    r: u32,
    p: u32,
}

#[derive(Serialize, Deserialize)]
pub struct CipherParams {
    iv: String,
}

#[derive(Serialize, Deserialize)]
pub struct Crypto {
    kdf: String,
    kdfparams: KdfParams,
    cipher: String,
    ciphertext: String,
    cipherparams: CipherParams,
    mac: String,
}

pub struct Encrypt {
    dklen: usize,
    log_n: u8,
    salt: Vec<u8>,
    iv: Vec<u8>,
}

impl Encrypt {
    pub fn new(dklen: usize, log_n: u8) -> Encrypt {
        Encrypt {
            dklen,
            log_n,
            salt: rand_bytes(dklen as usize),
            iv: rand_bytes(16),
        }
    }

    pub fn encrypt(&self, password: &str, data: &[u8]) -> Result<Crypto> {
        // make key first
        let key = make_key(password, &self.salt, self.log_n, 8, 1, self.dklen)?;
        // prepare content
        let mut content = vec![];
        content.extend_from_slice(data);
        // encrypt
        let key = GenericArray::clone_from_slice(key.as_slice());
        let iv = GenericArray::clone_from_slice(self.iv.as_slice());
        let mut aes = Aes128Ctr::new(&key, &iv);
        aes.apply_keystream(&mut content);
        let mac = make_mac(key.as_slice(), &content);
        // prepare result
        Ok(Crypto {
            kdf: "scrypt".to_owned(),
            kdfparams: KdfParams {
                dklen: self.dklen,
                salt: hex::encode(&self.salt),
                log_n: self.log_n,
                n: 2_u32.pow(self.log_n as u32),
                r: 8,
                p: 1,
            },
            cipher: "aes-128-ctr".to_owned(),
            ciphertext: hex::encode(&content),
            cipherparams: CipherParams {
                iv: hex::encode(&iv),
            },
            mac: hex::encode(mac),
        })
    }
}

pub struct Decrypt;

impl Decrypt {
    pub fn decrypt(password: &str, crypto: &Crypto) -> Result<Vec<u8>> {
        let salt = hex::decode(crypto.kdfparams.salt.clone())?;
        let key = make_key(
            password,
            salt.as_slice(),
            crypto.kdfparams.log_n,
            crypto.kdfparams.r,
            crypto.kdfparams.p,
            crypto.kdfparams.dklen,
        )?;
        let mut content = hex::decode(crypto.ciphertext.clone())?;
        let this_mac = make_mac(key.as_slice(), content.as_slice());
        let mac = hex::decode(crypto.mac.clone())?;
        if this_mac != mac {
            bail!("wrong password");
        }
        // ready to decrypt
        let key = GenericArray::from_slice(key.as_slice());
        let iv = hex::decode(crypto.cipherparams.iv.clone())?;
        let iv = GenericArray::from_slice(iv.as_slice());
        let mut aes = Aes128Ctr::new(&key, &iv);
        aes.apply_keystream(&mut content);
        Ok(content)
    }
}

fn make_key(
    password: &str,
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    dklen: usize,
) -> Result<Vec<u8>> {
    if dklen < 16 {
        bail!("invalid dklen");
    }
    let mut key = vec![];
    key.resize(dklen, 0);
    let params = Params::new(log_n, r, p, dklen)?;
    scrypt(password.as_bytes(), salt, &params, key.as_mut_slice())?;
    Ok(key[..16].into())
}

fn make_mac(key: &[u8], content: &[u8]) -> Vec<u8> {
    // calc mac
    let mut sha3 = Sha3_256::new();
    sha3.update(key);
    sha3.update(content);
    let res = sha3.finalize();
    res.to_vec()
}

#[cfg(test)]
mod tests {
    use super::{Decrypt, Encrypt};

    #[test]
    fn test_crypto_16() {
        const PLAIN_TEXT: &str = "hello world!";
        let encrypt = Encrypt::new(16, 16);
        let res = encrypt.encrypt("123", PLAIN_TEXT.as_bytes()).unwrap();
        let decrypted_data = Decrypt::decrypt("123", &res).unwrap();
        let decrypted_str = String::from_utf8(decrypted_data).unwrap();
        assert_eq!(decrypted_str, PLAIN_TEXT);
    }

    #[test]
    fn test_crypto_32() {
        const PLAIN_TEXT: &str = "hello world!";
        let encrypt = Encrypt::new(32, 16);
        let res = encrypt.encrypt("123", PLAIN_TEXT.as_bytes()).unwrap();
        let decrypted_data = Decrypt::decrypt("123", &res).unwrap();
        let decrypted_str = String::from_utf8(decrypted_data).unwrap();
        assert_eq!(decrypted_str, PLAIN_TEXT);
    }
}