# Rust File Encrypter (RFE)

RFE is a minimalist command-line utility designed for secure file encryption. It was built to demonstrate the implementation of Authenticated Encryption (AEAD) using the AES-256-GCM cipher suite.

```text
    ██████╗ ███████╗███████╗
    ██╔══██╗██╔════╝██╔════╝
    ██████╔╝█████╗  █████╗  
    ██╔══██╗██╔══╝  ██╔══╝  
    ██║  ██║██║     ███████╗
    ╚═╝  ╚═╝╚═╝     ╚══════╝ (v1.0.0)
```

## Technical Overview

The application utilizes the `aes-gcm` crate to provide both confidentiality and data integrity. Unlike standard block cipher modes, GCM includes an authentication tag; if the encrypted file is modified or corrupted, the decryption process will intentionally fail to prevent the use of tampered data.

Each encryption operation generates a unique 12-byte nonce using the system's cryptographically secure pseudorandom number generator (CSPRNG via the `rand` crate).

## Installation

Building from source requires a working Rust toolchain.

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/rust-file-encryptor.git](https://github.com/yourusername/rust-file-encryptor.git)
   ```

## Usage

The tool operates via simple flags and requires an input path.

### Encryption
To encrypt a file, use the `-e` flag:
```bash
./encrypter -e data.txt
```

## Security Considerations

This version (1.0.0) uses a static 32-byte key defined within the source code. While this is sufficient for testing and understanding the encryption pipeline, it should not be used for production environments where key management or password-based key derivation (PBKDF2/Argon2) is required.

## Specifications

* **Cipher:** AES-256-GCM
* **Key size:** 256 bits
* **Nonce:** 96 bits (randomized per execution)
* **Tag:** 128 bits (appended to ciphertext)

## License

MIT