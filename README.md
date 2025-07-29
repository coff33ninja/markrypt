# Markrypt

A comprehensive text obfuscation library that uses Markov chains for realistic noise generation and character substitution for encryption.

## Features

- **Character Substitution**: Unicode-based character mapping for encryption
- **Markov Noise**: Realistic noise insertion using vowel/consonant patterns
- **Multiple Modes**: Basic, full Unicode, and custom character ranges
- **Integrity Verification**: SHA-256 hash verification with salt
- **Metadata Encryption**: Optional AES-GCM encryption for metadata
- **QR Code Support**: Generate QR codes for encrypted messages
- **Batch Processing**: Encrypt/decrypt multiple messages at once
- **CLI Tools**: Command-line interfaces for all operations

## Installation

```bash
pip install markrypt
```

For full functionality with encryption and QR codes:

```bash
pip install markrypt[full]
```

Optional dependencies:

- `markrypt[crypto]` - AES encryption support
- `markrypt[qr]` - QR code generation
- `markrypt[api]` - FastAPI web service

## Quick Start

### Python API

```python
import markrypt

# Basic usage
mk = markrypt.Markrypt(noise=True, noise_style='markov')
encrypted = mk.encrypt("Hello World!", mapping_key="mykey")
decrypted = mk.decrypt(encrypted, mapping_key="mykey")

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

- **Noise Styles**: `markov`, `lowercase`, `custom`
- **Unicode Ranges**: `basic`, `full`, custom blocks
- **Symbol Preservation**: Keep or strip special characters
- **Integrity Checking**: SHA-256 verification
- **Metadata Encryption**: AES-GCM protection

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
    preserve_symbols=True
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

### File Operations

```python
from markrypt.encrypt import MarkryptEncryptor
from markrypt.decrypt import MarkryptDecryptor

# Encrypt file
encryptor = MarkryptEncryptor()
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
- `noise_style`: Type of noise ('markov', 'lowercase', 'custom')
- `unicode_range`: Character range ('basic', 'full')

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

## Dependencies

- **Core**: Python 3.8+, no external dependencies
- **Crypto**: `cryptography` library for AES encryption
- **QR**: `qrcode` and `Pillow` for QR code generation
- **API**: `fastapi` and `uvicorn` for web service

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.
