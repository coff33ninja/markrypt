"""
Core Markrypt functionality - the main Markrypt class with all encryption/decryption logic
"""

import random
import string
import json
import base64
import hashlib
import zlib
import os
import unicodedata
from .exceptions import MarkryptError, ValidationError, DecryptionError, IntegrityError
from .pqc import create_pqc_instance
from .steganography import create_steganography_instance

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import qrcode
    from PIL import Image
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False


class Markrypt:
    """
    Main Markrypt class for text obfuscation and encryption
    
    This class provides the core functionality for encrypting and decrypting text
    using character substitution and Markov-based noise insertion.
    """
    
    def __init__(self, seed=None, mapping_key=None, preserve_symbols=True, noise=True, 
                 noise_style='markov', custom_noise_chars=None, noise_exclude=None, 
                 unicode_range='basic', unicode_blocks=None, cipher_mode='substitution',
                 enable_pqc=False, enable_steganography=False):
        """
        Initialize Markrypt with configuration options
        
        Args:
            seed: Random seed for reproducibility
            mapping_key: Key for character mapping
            preserve_symbols: Keep symbols unchanged during encryption
            noise: Enable noise insertion
            noise_style: Style of noise ('markov', 'lowercase', 'custom', 'emoji')
            custom_noise_chars: Custom characters for noise (when style='custom')
            noise_exclude: Characters to exclude from noise
            unicode_range: Unicode range to use ('basic', 'full')
            unicode_blocks: Specific Unicode blocks to include
            cipher_mode: Encryption mode ('substitution', 'chacha20', 'pqc')
            enable_pqc: Enable post-quantum cryptography features
            enable_steganography: Enable steganography features
        """
        self.vowels = set('aeiouAEIOU')
        self.consonants = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
        self.transitions = {
            'vowel': {'vowel': 0.4, 'consonant': 0.6},
            'consonant': {'vowel': 0.6, 'consonant': 0.4}
        }
        
        # Configuration
        self.preserve_symbols = preserve_symbols
        self.noise = noise
        self.noise_style = noise_style
        self.custom_noise_chars = custom_noise_chars if custom_noise_chars else string.ascii_lowercase
        self.noise_exclude = set(noise_exclude or [])
        self.seed = seed
        self.unicode_range = unicode_range
        self.unicode_blocks = unicode_blocks or []
        self.cipher_mode = cipher_mode
        self.enable_pqc = enable_pqc
        self.enable_steganography = enable_steganography
        
        # Internal state
        self._char_map_cache = {}
        self.char_map = {}
        self.reverse_map = {}
        
        # Initialize optional modules
        self.pqc = create_pqc_instance() if enable_pqc else None
        self.steganography = create_steganography_instance() if enable_steganography else None
        
        if seed is not None:
            random.seed(seed)
        
        self._create_mappings(mapping_key)

    def _generate_random_key(self):
        """Generate a random 16-character key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def _stretch_key(self, key):
        """Stretch the key using PBKDF2 for enhanced security"""
        if not key:
            return ""
        return hashlib.pbkdf2_hmac('sha256', key.encode(), b'markrypt_salt', 100000).hex()

    def _create_mappings(self, mapping_key):
        """Create character mappings for printable Unicode characters"""
        if mapping_key in self._char_map_cache:
            self.char_map, self.reverse_map = self._char_map_cache[mapping_key]
            return
        
        # Build character set based on unicode_range
        if self.unicode_range == 'basic':
            all_chars = (
                list(string.ascii_letters + string.digits + string.punctuation) +
                [chr(i) for i in range(161, 256)] +
                ['😀', '😂', '😊', '🔥', '⭐', '💡', '🌍', '🚀'] +
                self._get_emoji_noise_chars()  # Include emoji noise chars in mapping
            )
        elif self.unicode_range == 'full':
            all_chars = [chr(i) for i in range(32, 0x110000) if unicodedata.category(chr(i))[0] != 'C']
        else:
            # Custom Unicode blocks
            all_chars = []
            for block in self.unicode_blocks:
                if block == 'Latin-1 Supplement':
                    all_chars.extend(chr(i) for i in range(161, 256))
                elif block == 'Emojis':
                    all_chars.extend(['😀', '😂', '😊', '🔥', '⭐', '💡', '🌍', '🚀'])
        
        # Create shifted mapping
        stretched_key = self._stretch_key(mapping_key)
        shift = sum(ord(c) for c in stretched_key) % len(all_chars) if stretched_key else 5
        shifted_chars = all_chars[shift:] + all_chars[:shift]
        
        self.char_map = dict(zip(all_chars, shifted_chars))
        self.reverse_map = dict(zip(shifted_chars, all_chars))
        self._char_map_cache[mapping_key] = (self.char_map, self.reverse_map)

    def _is_vowel(self, char):
        """Check if character is a vowel (ASCII only for Markov logic)"""
        return char.lower() in set('aeiou')

    def _get_next_char_type(self, current_type):
        """Get next character type based on Markov chain probabilities"""
        probs = self.transitions[current_type]
        return random.choices(
            ['vowel', 'consonant'],
            weights=[probs['vowel'], probs['consonant']],
            k=1
        )[0]

    def _validate_input(self, message):
        """Validate input message"""
        if not message:
            raise ValidationError("Message cannot be empty")
        return True

    def _validate_key(self, key, api_mode=False):
        """Validate mapping key"""
        if not key and api_mode:
            raise ValidationError("Mapping key is required in API mode")
        if not key:
            key = self._generate_random_key()
        if len(key) < 4:
            pass  # Warning handled by caller
        return key

    def _encrypt_metadata(self, metadata, mapping_key):
        """Encrypt metadata using AES-GCM"""
        if not CRYPTO_AVAILABLE:
            raise MarkryptError("Metadata encryption requires 'cryptography' library")
        key = hashlib.sha256(self._stretch_key(mapping_key).encode()).digest()
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        metadata_bytes = zlib.compress(json.dumps(metadata).encode('utf-8'))
        ciphertext = encryptor.update(metadata_bytes) + encryptor.finalize()
        return base64.b64encode(nonce + ciphertext + encryptor.tag).decode('utf-8')

    def _decrypt_metadata(self, metadata_b64, mapping_key):
        """Decrypt AES-encrypted metadata"""
        if not CRYPTO_AVAILABLE:
            raise MarkryptError("Metadata encryption requires 'cryptography' library")
        key = hashlib.sha256(self._stretch_key(mapping_key).encode()).digest()
        data = base64.b64decode(metadata_b64)
        nonce, ciphertext, tag = data[:16], data[16:-16], data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        metadata_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        return json.loads(zlib.decompress(metadata_bytes).decode('utf-8'))

    def _compute_integrity_hash(self, message, mapping_key, salt):
        """Compute SHA-256 hash with dynamic salt"""
        stretched_key = self._stretch_key(mapping_key) or ""
        return hashlib.sha256((message + stretched_key + salt).encode('utf-8')).hexdigest()

    def _generate_qr_code(self, data, filename):
        """Generate QR code for data"""
        if not QR_AVAILABLE:
            raise MarkryptError("QR code generation requires 'qrcode' and 'Pillow' libraries")
        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filename)
        return filename

    def _chacha20_encrypt(self, plaintext, key):
        """Encrypt using ChaCha20-Poly1305 AEAD cipher"""
        if not CRYPTO_AVAILABLE:
            raise MarkryptError("ChaCha20 encryption requires 'cryptography' library")
        
        # Derive 32-byte key from mapping key
        key_bytes = hashlib.sha256(self._stretch_key(key).encode()).digest()
        
        # Create ChaCha20Poly1305 cipher
        cipher = ChaCha20Poly1305(key_bytes)
        nonce = os.urandom(12)  # ChaCha20 uses 12-byte nonce
        
        # Encrypt the plaintext
        ciphertext = cipher.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Return base64-encoded nonce + ciphertext
        return base64.b64encode(nonce + ciphertext).decode('utf-8')

    def _chacha20_decrypt(self, ciphertext_b64, key):
        """Decrypt using ChaCha20-Poly1305 AEAD cipher"""
        if not CRYPTO_AVAILABLE:
            raise MarkryptError("ChaCha20 decryption requires 'cryptography' library")
        
        # Derive 32-byte key from mapping key
        key_bytes = hashlib.sha256(self._stretch_key(key).encode()).digest()
        
        # Create ChaCha20Poly1305 cipher
        cipher = ChaCha20Poly1305(key_bytes)
        
        # Decode and split nonce + ciphertext
        data = base64.b64decode(ciphertext_b64)
        nonce, ciphertext = data[:12], data[12:]
        
        # Decrypt and return plaintext
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

    def _pqc_encrypt(self, plaintext, recipient_public_key):
        """Encrypt using post-quantum cryptography (hybrid approach)"""
        if not self.pqc:
            raise MarkryptError("Post-quantum cryptography not enabled or available")
        
        # Use hybrid encryption for efficiency
        encrypted_data = self.pqc.hybrid_encrypt(plaintext, recipient_public_key)
        
        # Encode as base64 for storage
        return base64.b64encode(json.dumps(encrypted_data).encode('utf-8')).decode('utf-8')

    def _pqc_decrypt(self, ciphertext_b64, recipient_secret_key):
        """Decrypt using post-quantum cryptography"""
        if not self.pqc:
            raise MarkryptError("Post-quantum cryptography not enabled or available")
        
        # Decode and parse encrypted data
        encrypted_data = json.loads(base64.b64decode(ciphertext_b64).decode('utf-8'))
        
        # Decrypt using hybrid approach
        return self.pqc.hybrid_decrypt(encrypted_data, recipient_secret_key)

    def _get_emoji_noise_chars(self):
        """Get chaotic emoji characters for noise injection"""
        return [
            '🌪️', '🚀', '💥', '⚡', '🔥', '💫', '🌟', '✨', '🎆', '🎇',
            '🌈', '🌊', '🌀', '💨', '☄️', '🌙', '⭐', '🌞', '🌝', '🌛',
            '🎭', '🎪', '🎨', '🎯', '🎲', '🎰', '🎳', '🎮', '🕹️', '🎸',
            '🚁', '🛸', '🚂', '🚄', '🚅', '🚆', '🚇', '🚈', '🚉', '🚊',
            '🔮', '💎', '💍', '👑', '🏆', '🥇', '🥈', '🥉', '🏅', '🎖️',
            '🦄', '🐉', '🦋', '🐙', '🦑', '🐠', '🐡', '🦈', '🐳', '🐋'
        ]

    def encrypt(self, message, mapping_key=None, integrity_check=True, qr_file=None, 
                json_output=False, encrypt_metadata=False):
        """
        Encrypt the message with advanced options
        
        Args:
            message: Text to encrypt
            mapping_key: Encryption key
            integrity_check: Add integrity verification
            qr_file: Generate QR code to this file
            json_output: Return structured JSON
            encrypt_metadata: Use AES encryption for metadata
            
        Returns:
            Encrypted string or JSON object
        """
        try:
            self._validate_input(message)
            mapping_key = self._validate_key(mapping_key)
            
            # Handle ChaCha20 mode
            if self.cipher_mode == 'chacha20':
                encrypted_data = self._chacha20_encrypt(message, mapping_key)
                salt = os.urandom(16).hex() if integrity_check else ""
                output = f"v2:chacha20:{encrypted_data}:{salt}"
                
                if integrity_check:
                    integrity_hash = self._compute_integrity_hash(message, mapping_key, salt)
                    output += f":{integrity_hash}"
                
                if qr_file:
                    self._generate_qr_code(output, qr_file)
                
                if json_output:
                    return {
                        "version": "v2",
                        "cipher": "chacha20",
                        "data": encrypted_data,
                        "salt": salt,
                        "hash": integrity_hash if integrity_check else "",
                        "generated_key": mapping_key if not self._validate_key(mapping_key, api_mode=True) else None
                    }
                return output
            
            # Handle Post-Quantum Cryptography mode
            if self.cipher_mode == 'pqc':
                if not mapping_key:
                    raise ValidationError("PQC mode requires a recipient public key as mapping_key")
                
                encrypted_data = self._pqc_encrypt(message, mapping_key)
                salt = os.urandom(16).hex() if integrity_check else ""
                output = f"v3:pqc:{encrypted_data}:{salt}"
                
                if integrity_check:
                    integrity_hash = self._compute_integrity_hash(message, mapping_key, salt)
                    output += f":{integrity_hash}"
                
                if qr_file:
                    self._generate_qr_code(output, qr_file)
                
                if json_output:
                    return {
                        "version": "v3",
                        "cipher": "pqc",
                        "data": encrypted_data,
                        "salt": salt,
                        "hash": integrity_hash if integrity_check else "",
                        "recipient_public_key": mapping_key
                    }
                return output
            
            # Original substitution cipher mode
            self._create_mappings(mapping_key)
            
            # Set seed for consistent randomization
            if self.seed is not None:
                random.seed(self.seed)
            
            # Auto-disable noise for very large texts to prevent issues
            original_noise = self.noise
            noise_disabled_for_size = False
            if self.noise and len(message) > 1000:
                print(f"Warning: Disabling noise for large text ({len(message)} chars) to prevent processing issues")
                self.noise = False
                noise_disabled_for_size = True
            
            result = []
            metadata = []
            prev_type = 'vowel' if message and self._is_vowel(message[0]) else 'consonant'
            
            for i, char in enumerate(message):
                if char in self.char_map:
                    encrypted_char = self.char_map.get(char, char)
                    result.append(encrypted_char)
                    metadata.append(0)
                    
                    if self.noise:
                        if self.noise_style == 'markov':
                            next_type = self._get_next_char_type(prev_type)
                            candidates = list(self.vowels if next_type == 'vowel' else self.consonants)
                        elif self.noise_style == 'lowercase':
                            candidates = list(string.ascii_lowercase)
                        elif self.noise_style == 'custom':
                            candidates = list(self.custom_noise_chars)
                        elif self.noise_style == 'emoji':
                            candidates = self._get_emoji_noise_chars()
                        else:
                            raise ValidationError(f"Unknown noise style: {self.noise_style}")
                        
                        candidates = [c for c in candidates if c not in self.noise_exclude]
                        if not candidates:
                            raise ValidationError("No valid noise characters after exclusion")
                        random_char = random.choice(candidates)
                        if char.isupper() and random_char in string.ascii_letters:
                            random_char = random_char.upper()
                        result.append(random_char)
                        metadata.append(1)
                    prev_type = 'vowel' if self._is_vowel(char) else 'consonant'
                elif self.preserve_symbols:
                    result.append(char)
                    metadata.append(2)
            
            # Restore original noise setting
            self.noise = original_noise
            
            # Add a flag to metadata if noise was disabled for size
            if noise_disabled_for_size:
                # Store the original noise setting in the encrypted message for proper decryption
                pass  # The metadata already reflects no noise was added
            
            salt = os.urandom(16).hex() if integrity_check else ""
            metadata_b64 = self._encrypt_metadata(metadata, mapping_key) if encrypt_metadata and CRYPTO_AVAILABLE else base64.b64encode(zlib.compress(json.dumps(metadata).encode('utf-8'))).decode('utf-8')
            output_data = base64.b64encode(''.join(result).encode('utf-8')).decode('utf-8')
            output = f"v1:{metadata_b64}:{output_data}:{salt}"
            
            if integrity_check:
                integrity_hash = self._compute_integrity_hash(message, mapping_key, salt)
                output += f":{integrity_hash}"
            
            if qr_file:
                self._generate_qr_code(output, qr_file)
            
            if json_output:
                return {
                    "version": "v1",
                    "metadata": metadata_b64,
                    "data": output_data,
                    "salt": salt,
                    "hash": integrity_hash if integrity_check else "",
                    "generated_key": mapping_key if not self._validate_key(mapping_key, api_mode=True) else None
                }
            return output
        except Exception as e:
            raise MarkryptError(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_message, mapping_key=None, verify_integrity=True, encrypt_metadata=False):
        """
        Decrypt the message with optimized processing
        
        Args:
            encrypted_message: Encrypted text to decrypt
            mapping_key: Decryption key
            verify_integrity: Verify message integrity
            encrypt_metadata: Metadata is AES encrypted
            
        Returns:
            Decrypted text
        """
        try:
            self._validate_input(encrypted_message)
            mapping_key = self._validate_key(mapping_key)
            self._create_mappings(mapping_key)
            
            if self.seed is not None:
                random.seed(self.seed)
            
            parts = encrypted_message.split(':', 5)  # Split into max 6 parts
            if len(parts) < 4:
                raise DecryptionError("Invalid message format: insufficient parts")
            
            version = parts[0]
            if version not in ['v1', 'v2', 'v3']:
                raise DecryptionError(f"Unsupported version: {version}")
            
            # Handle ChaCha20 mode (v2)
            if version == 'v2' and len(parts) >= 4 and parts[1] == 'chacha20':
                encrypted_data, salt = parts[2], parts[3]
                integrity_hash = parts[4] if len(parts) > 4 and verify_integrity else None
                
                # Decrypt using ChaCha20
                decrypted_message = self._chacha20_decrypt(encrypted_data, mapping_key)
                
                # Verify integrity if requested
                if verify_integrity and integrity_hash:
                    computed_hash = self._compute_integrity_hash(decrypted_message, mapping_key, salt)
                    if computed_hash != integrity_hash:
                        raise IntegrityError("Integrity check failed: message may have been tampered")
                
                return decrypted_message
            
            # Handle Post-Quantum Cryptography mode (v3)
            if version == 'v3' and len(parts) >= 4 and parts[1] == 'pqc':
                encrypted_data, salt = parts[2], parts[3]
                integrity_hash = parts[4] if len(parts) > 4 and verify_integrity else None
                
                # Decrypt using PQC (mapping_key should be recipient's secret key)
                decrypted_message = self._pqc_decrypt(encrypted_data, mapping_key)
                
                # Verify integrity if requested
                if verify_integrity and integrity_hash:
                    computed_hash = self._compute_integrity_hash(decrypted_message, mapping_key, salt)
                    if computed_hash != integrity_hash:
                        raise IntegrityError("Integrity check failed: message may have been tampered")
                
                return decrypted_message
            
            # Handle original substitution cipher (v1)
            if version != 'v1':
                raise DecryptionError(f"Invalid message format for version {version}")
            
            metadata_b64, message_b64, salt = parts[1], parts[2], parts[3]
            integrity_hash = parts[4] if len(parts) > 4 and verify_integrity else None
            
            # Decode the base64-encoded message
            try:
                message = base64.b64decode(message_b64).decode('utf-8')
            except Exception as e:
                raise DecryptionError(f"Failed to decode message data: {str(e)}")
            
            if encrypt_metadata and CRYPTO_AVAILABLE:
                metadata = self._decrypt_metadata(metadata_b64, mapping_key)
            else:
                metadata_bytes = base64.b64decode(metadata_b64)
                metadata = json.loads(zlib.decompress(metadata_bytes).decode('utf-8'))
            
            # Calculate expected message length (all markers consume a character)
            expected_length = len(metadata)
            if expected_length > len(message):
                raise DecryptionError(f"Metadata requires {expected_length} message chars, got {len(message)}")
            
            result = []
            msg_index = 0
            for marker in metadata:
                if msg_index >= len(message):
                    raise DecryptionError(f"Message truncated: expected at least {expected_length} chars, got {msg_index}")
                
                if marker == 0:  # Original character (encrypted)
                    result.append(self.reverse_map.get(message[msg_index], message[msg_index]))
                    msg_index += 1
                elif marker == 1:  # Noise character (skip)
                    msg_index += 1
                elif marker == 2:  # Preserved symbol
                    result.append(message[msg_index])
                    msg_index += 1
            
            decrypted_message = ''.join(result)
            if verify_integrity and integrity_hash:
                computed_hash = self._compute_integrity_hash(decrypted_message, mapping_key, salt)
                if computed_hash != integrity_hash:
                    raise IntegrityError("Integrity check failed: message may have been tampered")
            
            return decrypted_message
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}")

    def encrypt_and_hide_in_image(self, message, mapping_key, image_path, output_path, 
                                  stego_password=None, **encrypt_kwargs):
        """
        Encrypt message and hide it in an image using steganography
        
        Args:
            message: Text to encrypt and hide
            mapping_key: Encryption key
            image_path: Path to cover image
            output_path: Path for output image with hidden message
            stego_password: Optional password for steganography layer
            **encrypt_kwargs: Additional arguments for encryption
            
        Returns:
            dict with operation details
        """
        if not self.steganography:
            raise MarkryptError("Steganography not enabled or available")
        
        # First encrypt the message
        encrypted_message = self.encrypt(message, mapping_key, **encrypt_kwargs)
        
        # Then hide the encrypted message in the image
        result = self.steganography.hide_message_in_image(
            encrypted_message, image_path, output_path, stego_password
        )
        
        result['original_message_length'] = len(message)
        result['encrypted_message_length'] = len(encrypted_message)
        return result

    def extract_and_decrypt_from_image(self, image_path, mapping_key, 
                                       stego_password=None, **decrypt_kwargs):
        """
        Extract hidden message from image and decrypt it
        
        Args:
            image_path: Path to image with hidden message
            mapping_key: Decryption key
            stego_password: Password for steganography layer
            **decrypt_kwargs: Additional arguments for decryption
            
        Returns:
            Decrypted message
        """
        if not self.steganography:
            raise MarkryptError("Steganography not enabled or available")
        
        # Extract encrypted message from image
        encrypted_message = self.steganography.extract_message_from_image(
            image_path, stego_password
        )
        
        # Decrypt the extracted message
        return self.decrypt(encrypted_message, mapping_key, **decrypt_kwargs)

    def generate_pqc_keypair(self, key_type='kyber'):
        """
        Generate post-quantum cryptography keypair
        
        Args:
            key_type: Type of keypair ('kyber' for KEM, 'dilithium' for signatures)
            
        Returns:
            dict with public_key and secret_key
        """
        if not self.pqc:
            raise MarkryptError("Post-quantum cryptography not enabled or available")
        
        if key_type == 'kyber':
            return self.pqc.generate_kyber_keypair()
        elif key_type == 'dilithium':
            return self.pqc.generate_dilithium_keypair()
        else:
            raise ValidationError(f"Unknown key type: {key_type}")

    def sign_message(self, message, secret_key):
        """
        Sign message using Dilithium post-quantum signature
        
        Args:
            message: Message to sign
            secret_key: Dilithium secret key (base64)
            
        Returns:
            Base64-encoded signature
        """
        if not self.pqc:
            raise MarkryptError("Post-quantum cryptography not enabled or available")
        
        return self.pqc.dilithium_sign(message, secret_key)

    def verify_signature(self, message, signature, public_key):
        """
        Verify Dilithium signature
        
        Args:
            message: Original message
            signature: Base64-encoded signature
            public_key: Dilithium public key (base64)
            
        Returns:
            bool indicating if signature is valid
        """
        if not self.pqc:
            raise MarkryptError("Post-quantum cryptography not enabled or available")
        
        return self.pqc.dilithium_verify(message, signature, public_key)

    def analyze_image_capacity(self, image_path):
        """
        Analyze image for steganography capacity
        
        Args:
            image_path: Path to image
            
        Returns:
            dict with capacity analysis
        """
        if not self.steganography:
            raise MarkryptError("Steganography not enabled or available")
        
        return self.steganography.analyze_image_for_steganography(image_path)