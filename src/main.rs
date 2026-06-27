use aes_gcm::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

// 64 KB plaintext per chunk; each encrypted chunk is CHUNK_SIZE + 16 (GCM tag)
const CHUNK_SIZE: usize = 64 * 1024;
const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 8;

// File format:
// [16-byte Argon2 salt][8-byte nonce prefix][8-byte chunk count u64 LE][encrypted chunks...]
// Each chunk: encrypt(plaintext_chunk, nonce=[prefix||chunk_index u32 LE], aad=chunk_index u64 LE)
// Ciphertext chunk size = plaintext chunk size + 16 (GCM tag); last chunk may be shorter

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let salt_b64 = argon2::password_hash::SaltString::encode_b64(salt)
        .expect("salt encoding failed");
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt_b64)
        .expect("key derivation failed");
    let bytes = hash.hash.expect("hash missing");
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes.as_bytes()[..32]);
    key
}

fn chunk_nonce(prefix: &[u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&index.to_le_bytes());
    nonce
}

// Read up to buf.len() bytes, stopping at EOF. Returns bytes read.
fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn prompt_password(confirm: bool) -> String {
    let password = rpassword::prompt_password("Password: ").expect("failed to read password");
    if confirm {
        let again =
            rpassword::prompt_password("Confirm password: ").expect("failed to read password");
        if password != again {
            eprintln!("Error: Passwords do not match.");
            process::exit(1);
        }
    }
    password
}

fn encrypt_file(input_path: &str, output_path: &str, force: bool) -> std::io::Result<()> {
    if !Path::new(input_path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Input file not found: {}", input_path),
        ));
    }

    if !force && Path::new(output_path).exists() {
        eprintln!(
            "Error: Output file '{}' already exists. Use --force to overwrite.",
            output_path
        );
        process::exit(1);
    }

    let password = prompt_password(true);

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(&password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    OsRng.fill_bytes(&mut nonce_prefix);

    let file_size = std::fs::metadata(input_path)?.len();
    let chunk_count: u64 = if file_size == 0 {
        0
    } else {
        (file_size + CHUNK_SIZE as u64 - 1) / CHUNK_SIZE as u64
    };

    let mut input = BufReader::new(File::open(input_path)?);
    let mut output = BufWriter::new(File::create(output_path)?);

    output.write_all(&salt)?;
    output.write_all(&nonce_prefix)?;
    output.write_all(&chunk_count.to_le_bytes())?;

    let mut buf = vec![0u8; CHUNK_SIZE];
    for i in 0..chunk_count {
        let nonce_bytes = chunk_nonce(&nonce_prefix, i as u32);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let n = read_chunk(&mut input, &mut buf)?;
        let aad = i.to_le_bytes();
        let ciphertext = cipher
            .encrypt(nonce, Payload { msg: &buf[..n], aad: &aad })
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        output.write_all(&ciphertext)?;
    }

    output.flush()?;
    Ok(())
}

fn decrypt_file(input_path: &str, output_path: &str, force: bool) -> std::io::Result<()> {
    if !Path::new(input_path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("File not found: {}", input_path),
        ));
    }

    if !force && Path::new(output_path).exists() {
        eprintln!(
            "Error: Output file '{}' already exists. Use --force to overwrite.",
            output_path
        );
        process::exit(1);
    }

    let mut input = BufReader::new(File::open(input_path)?);

    let mut salt = [0u8; SALT_LEN];
    input.read_exact(&mut salt)?;

    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    input.read_exact(&mut nonce_prefix)?;

    let mut count_bytes = [0u8; 8];
    input.read_exact(&mut count_bytes)?;
    let chunk_count = u64::from_le_bytes(count_bytes);

    let password = prompt_password(false);
    let key = derive_key(&password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut output = BufWriter::new(File::create(output_path)?);
    let mut buf = vec![0u8; CHUNK_SIZE + 16];

    for i in 0..chunk_count {
        let nonce_bytes = chunk_nonce(&nonce_prefix, i as u32);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = i.to_le_bytes();

        // All chunks except the last are exactly CHUNK_SIZE + 16 bytes
        let n = if i < chunk_count - 1 {
            input.read_exact(&mut buf)?;
            CHUNK_SIZE + 16
        } else {
            read_chunk(&mut input, &mut buf)?
        };

        let plaintext = cipher
            .decrypt(nonce, Payload { msg: &buf[..n], aad: &aad })
            .map_err(|_| {
                std::io::Error::other(
                    "Decryption failed: wrong password or file is corrupted.",
                )
            })?;

        output.write_all(&plaintext)?;
    }

    output.flush()?;
    Ok(())
}

fn decrypt_output_path(input: &str) -> String {
    let path = PathBuf::from(input);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(input);
    let parent = path.parent().unwrap_or(Path::new(""));
    parent.join(format!("{}.dec", stem)).to_string_lossy().into_owned()
}

fn print_usage() {
    println!("Usage:");
    println!("  Encrypt:  encrypter -e <file> [--force]");
    println!("  Decrypt:  encrypter -d <file.enc> [--force]");
    println!();
    println!("Options:");
    println!("  --force       Overwrite output file if it exists");
    println!("  -h, --help    Show this help message");
}

fn main() {
    println!(
        r#"
    ██████╗ ███████╗███████╗
    ██╔══██╗██╔════╝██╔════╝
    ██████╔╝█████╗  █████╗
    ██╔══██╗██╔══╝  ██╔══╝
    ██║  ██║██║     ███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝ (v1.1.0)
    "#
    );

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        print_usage();
        process::exit(if args.len() < 3 { 1 } else { 0 });
    }

    let mode = &args[1];
    let input = &args[2];
    let force = args.contains(&"--force".to_string());

    let result = match mode.as_str() {
        "-e" => {
            let output = format!("{}.enc", input);
            encrypt_file(input, &output, force).map(|_| {
                println!("DONE: Encrypted to {}", output);
            })
        }
        "-d" => {
            let output = decrypt_output_path(input);
            decrypt_file(input, &output, force).map(|_| {
                println!("DONE: Decrypted to {}", output);
            })
        }
        _ => {
            eprintln!("Error: Use -e (encrypt) or -d (decrypt).");
            print_usage();
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
