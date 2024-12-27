use std::io::Write;
use std::{fs, io};

use anyhow::Result;
use clap::{Parser, Subcommand};
mod crypto;

use crypto::prelude::*;

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
    #[arg(short, long)]
    output_file: String,
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
            let data = fs::read(&encrypt.input_file)?;
            let encrypt = AESEncrypt::new(32, 16);
            let crypto = encrypt.encrypt(&password, data.as_slice())?;
            let out_str = serde_json::to_string(&crypto).unwrap();
            println!("{}", out_str);
        }
        Commands::Decrypt(decrypt) => {
            let password = read_password()?;
            let data = fs::read(decrypt.input_file.clone())?;
            let json_str = String::from_utf8(data)?;
            let crypto: Crypto = serde_json::from_str(&json_str).unwrap();
            let decrypted_data = AESDecrypt::decrypt(&password, &crypto)?;
            fs::write(&decrypt.output_file, decrypted_data)?;
            println!("wrote decrypted data to file {}", decrypt.output_file);
        }
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
