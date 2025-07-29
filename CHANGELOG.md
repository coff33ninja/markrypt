# Changelog

All notable changes to Markrypt will be documented in this file.

## [2.3.0] - 2025-01-29

### 🎉 Major New Features

#### 🔮 Post-Quantum Cryptography

- **Kyber KEM**: Quantum-resistant key encapsulation mechanism for secure key exchange
- **Dilithium Signatures**: Post-quantum digital signatures for authentication and integrity
- **Hybrid Encryption**: Combines PQC with traditional AES for efficiency and security
- **v3 Format**: New message format `v3:pqc:` supporting post-quantum algorithms
- **CLI Support**: `markrypt pqc-keygen` command for generating Kyber/Dilithium keypairs

#### 🖼️ Steganography

- **LSB Hiding**: Hide encrypted messages in images using Least Significant Bit technique
- **Password Protection**: Additional steganography-layer password protection
- **Capacity Analysis**: Analyze images for message hiding capacity with `stego-analyze`
- **Cover Image Generation**: Create suitable cover images with various patterns (random, gradient, noise)
- **CLI Tools**: `markrypt stego-hide`, `stego-extract`, `stego-analyze` commands

#### 🛡️ Enhanced Security

- **Multiple Cipher Modes**: substitution, chacha20, pqc
- **Hybrid Security**: Combine multiple techniques (e.g., ChaCha20 + Steganography + PQC)
- **Version Compatibility**: Backward compatible with v1, v2, and new v3 formats
- **Enhanced Key Stretching**: PBKDF2 with 100,000 iterations for all modes

### Added

- Post-quantum cryptography module (`markrypt.pqc`) with Kyber and Dilithium support
- Steganography module (`markrypt.steganography`) with LSB hiding and image analysis
- New CLI commands: `pqc-keygen`, `stego-hide`, `stego-extract`, `stego-analyze`
- Comprehensive test suite for PQC and steganography features
- Enhanced examples demonstrating all new features
- Optional dependency groups: `[pqc]`, `[stego]`, `[full]`
- Hybrid encryption methods combining multiple security layers
- Digital signature support with quantum-resistant Dilithium algorithm
- Image capacity analysis and cover image generation tools
- Enhanced error handling for graceful degradation when optional dependencies missing

### Changed

- Updated package version to 2.3.0
- Enhanced CLI with new commands and comprehensive help system
- Improved documentation with extensive examples for all features
- Better dependency management with optional extras for specific features
- Enhanced deployment script with feature testing and validation
- Updated README with post-quantum and steganography sections

### Dependencies

- **New Optional**: `pqcrypto`, `kyber-py` for post-quantum cryptography
- **New Optional**: `Pillow`, `numpy` for steganography and image processing
- **Existing**: `cryptography` for ChaCha20 and AES encryption
- **Existing**: `qrcode[pil]` for QR code generation

### Installation Options

```bash
pip install markrypt           # Core features only
pip install markrypt[full]     # All features included
pip install markrypt[pqc]      # Post-quantum cryptography
pip install markrypt[stego]    # Steganography features
pip install markrypt[crypto]   # Enhanced encryption (ChaCha20)
```

### Security Notes

- Post-quantum cryptography provides protection against quantum computer attacks
- Steganography adds security through obscurity by hiding encrypted data in images
- Hybrid approaches combine multiple security techniques for defense in depth
- All encryption modes support integrity checking and authentication

## [2.0.0] - 2025-01-29

### Added

- **ChaCha20 Stream Cipher**: New `cipher_mode='chacha20'` option for stronger encryption using ChaCha20-Poly1305 AEAD
- **Emoji Noise Mode**: New `noise_style='emoji'` option for chaotic emoji injection (🌪️🚀💥⚡🔥)
- **Version 2 Format**: New v2 message format for ChaCha20 encrypted messages
- **Backward Compatibility**: Full support for decrypting v1 format messages
- **Enhanced CLI**: Added `--cipher-mode` and `--noise-style emoji` options
- **PyPI Ready**: Complete package preparation for pip installation

### Changed

- Updated version to 2.0.0
- Enhanced README with new feature documentation
- Improved examples with ChaCha20 and emoji demonstrations
- Extended CLI help text with new options

### Security

- ChaCha20-Poly1305 provides authenticated encryption with associated data (AEAD)
- Stronger key derivation for ChaCha20 mode
- Maintained integrity checking for both cipher modes

## [1.0.0] - 2024-12-XX

### Added

- Initial release with character substitution encryption
- Markov-based noise insertion
- Multiple Unicode ranges support
- Integrity verification with SHA-256
- Metadata encryption with AES-GCM
- QR code generation support
- Batch processing capabilities
- Comprehensive CLI tools
- High-level encryption/decryption APIs

### Features

- Character mapping encryption
- Vowel/consonant Markov chains for realistic noise
- Symbol preservation options
- Custom noise character sets
- File encryption/decryption
- JSON output format
- Test suite with multiple levels
