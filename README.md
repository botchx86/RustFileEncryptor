# Rust File Encrypter (RFE)

RFE is a minimalist command-line utility for secure file encryption. It demonstrates Authenticated Encryption (AEAD) using AES-256-GCM with password-based key derivation.

```text
    ██████╗ ███████╗███████╗
    ██╔══██╗██╔════╝██╔════╝
    ██████╔╝█████╗  █████╗
    ██╔══██╗██╔══╝  ██╔══╝
    ██║  ██║██║     ███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝ (v1.1.0)
```

## Technical Overview

RFE uses the `aes-gcm` crate for authenticated encryption. The GCM authentication tag means any modification to the encrypted file will cause decryption to fail, preventing use of tampered data.

Keys are never stored. Each encryption operation:
1. Prompts for a password
2. Generates a random 16-byte salt and derives a 256-bit AES key via Argon2id
3. Splits the file into 64 KB chunks and encrypts each independently using a unique per-chunk nonce
4. Each chunk's index is included as authenticated additional data (AAD), preventing chunk reordering attacks

The output `.enc` file layout is:

```
[16-byte Argon2 salt][8-byte nonce prefix][8-byte chunk count][encrypted chunk 0][encrypted chunk 1]...
```

Each encrypted chunk = plaintext chunk + 16-byte GCM authentication tag. Files of any size are handled with constant memory usage (~64 KB working buffer).

## Installation

Requires a working Rust toolchain ([rustup.rs](https://rustup.rs)).

```bash
git clone https://github.com/botchx86/RustFileEncryptor.git
cd RustFileEncryptor
cargo build --release
# Binary is at ./target/release/RustEncryptor
```

## Usage

### Encrypt a file

```bash
./RustEncryptor -e data.txt
# Prompts for a password (twice to confirm)
# Output: data.txt.enc
```

### Decrypt a file

```bash
./RustEncryptor -d data.txt.enc
# Prompts for the password
# Output: data.txt.dec
```

### Options

| Flag | Description |
|------|-------------|
| `-e <file>` | Encrypt the given file |
| `-d <file.enc>` | Decrypt the given file |
| `--force` | Overwrite the output file if it already exists |
| `-h`, `--help` | Show usage information |

## Security Considerations

- **Password strength matters** — the security of the encrypted file depends entirely on the password chosen. Use a strong, unique password.
- **Argon2id key derivation** — the password is never used as the key directly. Argon2id (memory-hard KDF) is used to derive the AES key, making brute-force attacks expensive.
- **No key storage** — the derived key exists only in memory during the operation and is never written to disk.
- **Streaming processing** — files are encrypted and decrypted in 64 KB chunks, so memory usage stays constant regardless of file size.

## Specifications

| Property | Value |
|----------|-------|
| Cipher | AES-256-GCM |
| Key size | 256 bits |
| Key derivation | Argon2id (default parameters) |
| Salt | 128 bits (random, stored in `.enc` file) |
| Nonce | 96 bits (random, stored in `.enc` file) |
| Auth tag | 128 bits (appended to ciphertext) |

## License

MIT
