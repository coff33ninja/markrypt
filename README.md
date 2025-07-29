# Markrypt

A comprehensive text obfuscation library with post-quantum cryptography, steganography, and advanced encryption features.

## Features

- **🔮 Post-Quantum Cryptography**: Kyber KEM and Dilithium signatures for quantum-resistant security
- **🖼️ Steganography**: Hide encrypted messages in images using LSB technique
- **🔐 Multiple Cipher Modes**: Character substitution, ChaCha20 stream cipher, and PQC hybrid encryption
- **🎭 Markov Noise**: Realistic noise insertion using vowel/consonant patterns
- **😄 Emoji Noise Mode**: Chaotic emoji injection for enhanced obfuscation
- **🌐 Unicode Support**: Basic, full Unicode, and custom character ranges
- **✅ Integrity Verification**: SHA-256 hash verification with salt
- **🔒 Metadata Encryption**: Optional AES-GCM encryption for metadata
- **📱 QR Code Support**: Generate QR codes for encrypted messages
- **⚡ Batch Processing**: Encrypt/decrypt multiple messages at once
- **💻 CLI Tools**: Command-line interfaces for all operations

## Installation

```bash
pip install markrypt
```

For full functionality with all features:

```bash
pip install markrypt[full]
```

Optional dependencies:

- `markrypt[crypto]` - AES encryption support
- `markrypt[qr]` - QR code generation
- `markrypt[pqc]` - Post-quantum cryptography
- `markrypt[stego]` - Steganography features
- `markrypt[api]` - FastAPI web service
- `markrypt[full]` - All features included

## Quick Start

### Python API

```python
import markrypt

# Basic usage
mk = markrypt.Markrypt(noise=True, noise_style='markov')
encrypted = mk.encrypt("Hello World!", mapping_key="mykey")
decrypted = mk.decrypt(encrypted, mapping_key="mykey")

# Post-quantum cryptography
mk_pqc = markrypt.Markrypt(enable_pqc=True, cipher_mode='pqc')
keypair = mk_pqc.generate_pqc_keypair('kyber')
encrypted = mk_pqc.encrypt("Secret message", mapping_key=keypair['public_key'])
decrypted = mk_pqc.decrypt(encrypted, mapping_key=keypair['secret_key'])

# Steganography
mk_stego = markrypt.Markrypt(enable_steganography=True)
result = mk_stego.encrypt_and_hide_in_image("Secret", "key", "cover.png", "hidden.png")
extracted = mk_stego.extract_and_decrypt_from_image("hidden.png", "key")

# High-level interfaces
encryptor = markrypt.encrypt.MarkryptEncryptor(seed=42)
encrypted = encryptor.encrypt_text("Secret message", key="mykey")

decryptor = markrypt.decrypt.MarkryptDecryptor()
decrypted = decryptor.decrypt_text(encrypted, key="mykey")
```

### Command Line

```bash
# Main CLI
markrypt encrypt "Hello World" --key mykey
markrypt decrypt "v1:..." --key mykey

# Dedicated tools
markrypt-encrypt "Hello World" --key mykey --qr-file qr.png
markrypt-decrypt "v1:..." --key mykey --analyze

# Get suggestions
markrypt-encrypt "Hello World" --suggest
markrypt-decrypt "v1:..." --key mykey --check-key
```

## Core Features

### Encryption Options

- **Cipher Modes**: `substitution` (character mapping), `chacha20` (stream cipher), `pqc` (post-quantum)
- **Noise Styles**: `markov`, `lowercase`, `custom`, `emoji`
- **Unicode Ranges**: `basic`, `full`, custom blocks
- **Symbol Preservation**: Keep or strip special characters
- **Integrity Checking**: SHA-256 verification
- **Metadata Encryption**: AES-GCM protection
- **Post-Quantum Features**: Kyber KEM, Dilithium signatures
- **Steganography**: LSB hiding in images with password protection

### Decryption Features

- **Format Validation**: Verify message structure
- **Corruption Detection**: Identify damaged messages
- **Key Strength Analysis**: Security recommendations
- **Batch Processing**: Handle multiple messages
- **Safe Mode**: Enhanced error handling

## Examples

### Basic Encryption/Decryption

```python
from markrypt import Markrypt

# Initialize with options
mk = Markrypt(
    seed=42,
    noise=True,
    noise_style='markov',
    preserve_symbols=True,
    cipher_mode='substitution'  # or 'chacha20'
)

# Encrypt
message = "This is a secret message!"
encrypted = mk.encrypt(message, mapping_key="supersecret")
print(f"Encrypted: {encrypted}")

# Decrypt
decrypted = mk.decrypt(encrypted, mapping_key="supersecret")
print(f"Decrypted: {decrypted}")
```

### High-Level Encryption

```python
from markrypt.encrypt import MarkryptEncryptor

encryptor = MarkryptEncryptor(noise_style='markov')

# Encrypt with QR code
encrypted = encryptor.encrypt_with_qr(
    "Secret message",
    key="mykey",
    qr_file="secret.png"
)

# Batch encrypt
messages = ["Hello", "World", "Secret"]
results = encryptor.batch_encrypt(messages, key="batchkey")
```

### Advanced Decryption

```python
from markrypt.decrypt import MarkryptDecryptor

decryptor = MarkryptDecryptor()

# Decrypt with analysis
result = decryptor.decrypt_with_analysis(encrypted, key="mykey")
print(f"Decrypted: {result['decrypted']}")
print(f"Analysis: {result['analysis']}")

# Safe decryption
result = decryptor.safe_decrypt(encrypted, key="mykey")
if result['success']:
    print(f"Safely decrypted: {result['decrypted']}")
else:
    print(f"Decryption failed: {result['error']}")
```

### ChaCha20 Stream Cipher

```python
from markrypt import Markrypt

# Use ChaCha20 for stronger encryption
mk = Markrypt(cipher_mode='chacha20')
encrypted = mk.encrypt("Secret message", mapping_key="strongkey")
decrypted = mk.decrypt(encrypted, mapping_key="strongkey")

# ChaCha20 with emoji noise
mk = Markrypt(cipher_mode='chacha20', noise_style='emoji')
encrypted = mk.encrypt("Top secret! 🔒", mapping_key="mykey")
```

### Emoji Noise Mode

```python
from markrypt import Markrypt

# Chaotic emoji injection
mk = Markrypt(noise_style='emoji', noise=True)
encrypted = mk.encrypt("Hello World", mapping_key="key")
# Result includes random emojis: "H🌪️e🚀l💥l⚡o🔥 W💫o🌟r✨l🎆d"

# Combine with ChaCha20 for maximum security
mk = Markrypt(cipher_mode='chacha20', noise_style='emoji')
encrypted = mk.encrypt("Classified data", mapping_key="topSecret")
```

### Post-Quantum Cryptography

```python
from markrypt import Markrypt

# Enable post-quantum cryptography
mk = Markrypt(enable_pqc=True, cipher_mode='pqc')

# Generate Kyber keypair for encryption
keypair = mk.generate_pqc_keypair('kyber')
public_key = keypair['public_key']
secret_key = keypair['secret_key']

# Encrypt with quantum-resistant algorithm
encrypted = mk.encrypt("Quantum-safe message", mapping_key=public_key)
decrypted = mk.decrypt(encrypted, mapping_key=secret_key)

# Digital signatures with Dilithium
sig_keypair = mk.generate_pqc_keypair('dilithium')
signature = mk.sign_message("Important document", sig_keypair['secret_key'])
is_valid = mk.verify_signature("Important document", signature, sig_keypair['public_key'])
```

### Steganography

```python
from markrypt import Markrypt

# Enable steganography
mk = Markrypt(enable_steganography=True)

# Analyze image capacity
analysis = mk.analyze_image_capacity("cover_image.png")
print(f"Can hide {analysis['capacity_chars']} characters")

# Encrypt and hide message in image
result = mk.encrypt_and_hide_in_image(
    message="Secret message",
    mapping_key="encryption_key",
    image_path="cover_image.png",
    output_path="image_with_secret.png",
    stego_password="stego_password"
)

# Extract and decrypt hidden message
extracted = mk.extract_and_decrypt_from_image(
    image_path="image_with_secret.png",
    mapping_key="encryption_key",
    stego_password="stego_password"
)

# Create cover images for steganography
mk.steganography.create_cover_image(
    width=800, height=600, pattern='random', output_path='cover.png'
)
```

### File Operations

```python
from markrypt.encrypt import MarkryptEncryptor
from markrypt.decrypt import MarkryptDecryptor

# Encrypt file with ChaCha20
encryptor = MarkryptEncryptor(cipher_mode='chacha20')
encryptor.encrypt_file("message.txt", "encrypted.txt", key="filekey")

# Decrypt file
decryptor = MarkryptDecryptor()
decryptor.decrypt_file("encrypted.txt", "decrypted.txt", key="filekey")
```

## CLI Usage

### Encryption CLI

```bash
# Basic encryption
markrypt-encrypt "Hello World" --key mykey

# File encryption with QR code
markrypt-encrypt --input-file message.txt --key mykey --qr-file qr.png

# Get encryption suggestions
markrypt-encrypt "Hello World" --suggest

# Batch encryption
markrypt-encrypt --batch messages.json --output-file results.json

# Custom noise settings
markrypt-encrypt "Hello" --noise-style custom --custom-noise "xyz123"

# ChaCha20 encryption with emoji noise
markrypt-encrypt "Secret" --cipher-mode chacha20 --noise-style emoji
```

### Decryption CLI

```bash
# Basic decryption
markrypt-decrypt "v1:..." --key mykey

# Analyze encrypted message
markrypt-decrypt "v1:..." --key mykey --analyze

# Check key strength
markrypt-decrypt "v1:..." --key mykey --check-key

# Safe decryption with error handling
markrypt-decrypt "v1:..." --key mykey --safe

# Detect corruption
markrypt-decrypt "v1:..." --detect-corruption
```

## Configuration Options

### Core Options

- `seed`: Random seed for reproducibility
- `mapping_key`: Key for character substitution
- `preserve_symbols`: Keep symbols unchanged
- `noise`: Enable noise insertion
- `noise_style`: Type of noise ('markov', 'lowercase', 'custom', 'emoji')
- `unicode_range`: Character range ('basic', 'full')
- `cipher_mode`: Encryption mode ('substitution', 'chacha20')

### Advanced Options

- `custom_noise_chars`: Custom noise character set
- `noise_exclude`: Characters to exclude from noise
- `unicode_blocks`: Specific Unicode blocks
- `integrity_check`: Enable SHA-256 verification
- `encrypt_metadata`: Use AES encryption for metadata

## Security Notes

- Use strong, unique keys for each message
- Enable integrity checking for important data
- Consider metadata encryption for sensitive applications
- Keys are stretched using PBKDF2 with 100,000 iterations
- Salt is randomly generated for each encryption
- ChaCha20 mode provides authenticated encryption with stronger security than substitution mode
- Emoji noise mode is experimental and may have encoding limitations with integrity checking

## Dependencies

- **Core**: Python 3.8+, no external dependencies
- **Crypto**: `cryptography` library for AES encryption and ChaCha20
- **QR**: `qrcode` and `Pillow` for QR code generation
- **PQC**: `pqcrypto` and `kyber-py` for post-quantum cryptography
- **Steganography**: `Pillow`, `numpy` for image processing
- **API**: `fastapi` and `uvicorn` for web service

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.
