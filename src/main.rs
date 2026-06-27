use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let salt_b64 = argon2::password_hash::SaltString::encode_b64(salt)
        .expect("salt encoding failed");
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt_b64)
        .expect("key derivation failed");
    let hash_bytes = hash.hash.expect("hash missing");
    let bytes = hash_bytes.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    key
}

fn prompt_password(confirm: bool) -> String {
    let password = rpassword::prompt_password("Password: ").expect("failed to read password");
    if confirm {
        let again = rpassword::prompt_password("Confirm password: ").expect("failed to read password");
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

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut data = Vec::new();
    File::open(input_path)?.read_to_end(&mut data)?;

    let ciphertext = cipher
        .encrypt(nonce, data.as_slice())
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut output_file = File::create(output_path)?;
    // File layout: [16-byte salt][12-byte nonce][ciphertext + 16-byte GCM tag]
    output_file.write_all(&salt)?;
    output_file.write_all(&nonce_bytes)?;
    output_file.write_all(&ciphertext)?;
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

    let password = prompt_password(false);

    let mut file = File::open(input_path)?;

    let mut salt = [0u8; SALT_LEN];
    file.read_exact(&mut salt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    file.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let key = derive_key(&password, &salt);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| std::io::Error::other(e.to_string()))?;

    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|_| {
        std::io::Error::other("Decryption failed: wrong password or file is corrupted.")
    })?;

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&plaintext)?;
    Ok(())
}

fn decrypt_output_path(input: &str) -> String {
    let path = PathBuf::from(input);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(input);
    let parent = path.parent().unwrap_or(Path::new(""));
    let out = parent.join(format!("{}.dec", stem));
    out.to_string_lossy().into_owned()
}

fn print_usage() {
    println!("Usage:");
    println!("  Encrypt:  encrypter -e <file> [--force]");
    println!("  Decrypt:  encrypter -d <file.enc> [--force]");
    println!();
    println!("Options:");
    println!("  --force   Overwrite output file if it exists");
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
