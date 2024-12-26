use std::io::Write;
use std::{fs, io};

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use anyhow::Result;
use clap::{Parser, Subcommand};
use ctr::Ctr128BE;
use scrypt::{
    password_hash::rand_core::{OsRng, RngCore},
    scrypt,
};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt(Encrypt),
    Decrypt(Decrypt),
    Verify(Verify),
}

#[derive(Parser)]
struct Encrypt {
    #[arg(short, long)]
    input_file: String,
}

#[derive(Parser)]
struct Decrypt {
    #[arg(short, long)]
    input_file: String,
}

#[derive(Parser)]
struct Verify {
    #[arg(short, long)]
    input_file: String,
}

#[derive(Serialize, Deserialize)]
struct KdfParams {
    dklen: u32,
    salt: String,
    n: u32,
    r: u32,
    p: u32,
}

#[derive(Serialize, Deserialize)]
struct CipherParams {
    iv: String,
}

#[derive(Serialize, Deserialize)]
struct Crypto {
    kdf: String,
    kdfparams: KdfParams,
    cipher: String,
    ciphertext: String,
    cipherparams: CipherParams,
}

fn read_password() -> Result<String> {
    print!("Enter password: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    // TODO check the password validity (length, cap letters, numbers etc)
    Ok(input)
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Encrypt(encrypt) => {
            let password = read_password()?;
            // create password
            let mut salt = [0u8; 16];
            OsRng.fill_bytes(&mut salt);
            let params = scrypt::Params::new(16, 8, 1, 16).unwrap();
            let mut key = [0u8; 16];
            scrypt(password.as_bytes(), &salt, &params, &mut key)?;
            // create iv
            let mut iv = [0u8; 16];
            OsRng.fill_bytes(&mut iv);
            type Aes128Ctr = Ctr128BE<Aes128>;
            // read source from file
            let mut content = fs::read(&encrypt.input_file)?;
            let mut aes = Aes128Ctr::new(&key.into(), &iv.into());
            aes.apply_keystream(&mut content);
            // write to file
            let crypto = Crypto {
                kdf: "scrypt".to_owned(),
                kdfparams: KdfParams {
                    dklen: 16,
                    salt: hex::encode(&salt),
                    n: 2_u32.pow(16),
                    r: 8,
                    p: 1,
                },
                cipher: "aes-128-ctr".to_owned(),
                ciphertext: hex::encode(&content),
                cipherparams: CipherParams {
                    iv: hex::encode(&iv),
                },
            };
            let out_str = serde_json::to_string(&crypto).unwrap();
            println!("{}", out_str);
        }
        Commands::Decrypt(decrypt) => todo!(),
        Commands::Verify(verify) => todo!(),
    }
    Ok(())
}

fn main() {
    let res = run();
    if let Err(e) = res {
        println!("error: {}", e);
        return;
    }
}
