use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

fn encrypt_file(key_bytes: &[u8], input_path: &str, output_path: &str) -> std::io::Result<()> {
    if !Path::new(input_path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Input file not found.",
        ));
    }

    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;

    let cipher =
        Aes256Gcm::new_from_slice(key_bytes).map_err(|e| std::io::Error::other(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Prefix the file with the random nonce
    output_file.write_all(&nonce_bytes)?;

    let mut data = Vec::new();
    input_file.read_to_end(&mut data)?;

    let ciphertext = cipher
        .encrypt(nonce, data.as_slice())
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    output_file.write_all(&ciphertext)?;
    Ok(())
}

fn decrypt_file(key_bytes: &[u8], input_path: &str, output_path: &str) -> std::io::Result<()> {
    if !Path::new(input_path).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found.",
        ));
    }

    let mut file = File::open(input_path)?;
    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let cipher =
        Aes256Gcm::new_from_slice(key_bytes).map_err(|e| std::io::Error::other(e.to_string()))?;

    let plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).map_err(|_| {
        std::io::Error::other("Decryption failed: Integrity check failed or invalid key.")
    })?;

    let mut output_file = File::create(output_path)?;
    output_file.write_all(&plaintext)?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    println!(
        r#"
    ██████╗ ███████╗███████╗
    ██╔══██╗██╔════╝██╔════╝
    ██████╔╝█████╗  █████╗  
    ██╔══██╗██╔══╝  ██╔══╝  
    ██║  ██║██║     ███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝ (v1.0.0)
    "#
    );

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        println!("Usage:");
        println!("  Encrypt:  encrypter -e <file>");
        println!("  Decrypt:  encrypter -d <file.enc>");
        return Ok(());
    }

    let mode = &args[1];
    let input = &args[2];
    let key = b"0123456789abcdef0123456789abcdef"; // 32-byte key for AES-256

    match mode.as_str() {
        "-e" => {
            let output = format!("{}.enc", input);
            encrypt_file(key, input, &output)?;
            println!("DONE: Encrypted to {}", output);
        }
        "-d" => {
            let output = input.replace(".enc", ".dec");
            decrypt_file(key, input, &output)?;
            println!("DONE: Decrypted to {}", output);
        }
        _ => eprintln!("Error: Use -e (encrypt) or -d (decrypt)."),
    }

    Ok(())
}
