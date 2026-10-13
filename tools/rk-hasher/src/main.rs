use std::io::{Seek, SeekFrom};

use sha2::{Digest, Sha256};
use sha3::{Sha3_256};
use md5::{Md5};
use clap::{Parser};
use hex;

#[derive(Parser,Debug)]
struct Cli {

    #[arg(long = "sha256",  default_value = "false", help = "Calculate SHA256 hash")]
    sha256:bool,

    #[arg(long = "sha3-256", default_value = "false", help = "Calculate SHA3-256 hash")]
    sha3_256:bool,

    #[arg(long = "md5", default_value = "false", help = "Calculate MD5 hash")]
    md5:bool,

    #[arg(value_name = "PATH")]
    path:String,
}

fn main() {
    let cli = Cli::parse();
    println!("Hashing file: {}", cli.path);

    let Ok(mut f) = std::fs::File::open(&cli.path) else {
        eprintln!("Error opening file: {}", cli.path);
        return;
    };

    if cli.sha3_256 {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut h = Sha3_256::new();
        std::io::copy(&mut f, &mut h).unwrap();
        println!("SHA3-256: \t{}", hex::encode(h.finalize()));
    }

    if cli.sha256 {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut h = Sha256::new();
        std::io::copy(&mut f, &mut h).unwrap();
        println!("SHA256: \t{}", hex::encode(h.finalize()));
    }

    if cli.md5 {
        f.seek(SeekFrom::Start(0)).unwrap();
        let mut h = Md5::new();
        std::io::copy(&mut f, &mut h).unwrap();
        println!("MD5: \t{}", hex::encode(h.finalize()));
    }
}
