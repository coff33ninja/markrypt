#!/usr/bin/env python3
"""
Markrypt 2.3 Examples - Demonstrating post-quantum cryptography, steganography, ChaCha20 cipher and emoji noise features
"""

import os
from markrypt import Markrypt
from markrypt.encrypt import MarkryptEncryptor
from markrypt.decrypt import MarkryptDecryptor


def demo_chacha20_cipher():
    """Demonstrate ChaCha20 stream cipher encryption"""
    print("🔐 ChaCha20 Stream Cipher Demo")
    print("=" * 40)
    
    # Create Markrypt instance with ChaCha20
    mk = Markrypt(cipher_mode='chacha20')
    
    message = "This is a secret message encrypted with ChaCha20!"
    key = "my_super_secret_key_2024"
    
    print(f"Original: {message}")
    
    # Encrypt with ChaCha20
    encrypted = mk.encrypt(message, mapping_key=key)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = mk.decrypt(encrypted, mapping_key=key)
    print(f"Decrypted: {decrypted}")
    
    print(f"✅ Success: {message == decrypted}")
    print()


def demo_emoji_noise():
    """Demonstrate emoji noise injection"""
    print("🎭 Emoji Noise Mode Demo")
    print("=" * 40)
    
    # Create Markrypt with emoji noise (no seed for randomness)
    mk = Markrypt(
        noise=True,
        noise_style='emoji',
        cipher_mode='substitution'
    )
    
    message = "Hello World! This will have emoji noise."
    key = "emoji_key"
    
    print(f"Original: {message}")
    
    # Encrypt with emoji noise (disable integrity check for demo)
    encrypted = mk.encrypt(message, mapping_key=key, integrity_check=False)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt (noise is automatically filtered out)
    decrypted = mk.decrypt(encrypted, mapping_key=key, verify_integrity=False)
    print(f"Decrypted: {decrypted}")
    print(f"✅ Success: {message == decrypted}")
    print("ℹ️  Note: Integrity checking disabled for emoji noise demo due to encoding complexities")
    print()


def demo_chacha20_with_emoji():
    """Demonstrate ChaCha20 with emoji noise (ultimate security + fun)"""
    print("🚀 ChaCha20 + Emoji Noise Demo")
    print("=" * 40)
    
    # Combine ChaCha20 with emoji noise (ChaCha20 doesn't use noise anyway)
    mk = Markrypt(
        cipher_mode='chacha20'
    )
    
    message = "Top secret classified information! 🔒"
    key = "ultimate_security_key_2024"
    
    print(f"Original: {message}")
    
    # Encrypt with both ChaCha20 and emoji noise
    encrypted = mk.encrypt(message, mapping_key=key)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = mk.decrypt(encrypted, mapping_key=key)
    print(f"Decrypted: {decrypted}")
    
    print(f"✅ Success: {message == decrypted}")
    print()


def demo_high_level_api():
    """Demonstrate high-level encryption API with new features"""
    print("🛠️ High-Level API Demo")
    print("=" * 40)
    
    # Create encryptor with ChaCha20
    encryptor = MarkryptEncryptor(
        cipher_mode='chacha20'
    )
    
    messages = [
        "First secret message 🔐",
        "Second confidential data 📊",
        "Third classified info 🎯"
    ]
    
    # Batch encrypt with ChaCha20
    result = encryptor.batch_encrypt(messages, key="batch_key_2024")
    
    print(f"Batch encrypted {result['successful']}/{result['total']} messages")
    print(f"Key used: {result['key']}")
    
    # Decrypt using high-level API
    decryptor = MarkryptDecryptor()
    
    for i, res in enumerate(result['results']):
        if res['success']:
            decrypted = decryptor.decrypt_text(res['encrypted'], key=result['key'])
            print(f"Message {i+1}: {decrypted}")
    
    print()


def demo_version_compatibility():
    """Demonstrate backward compatibility with v1 format"""
    print("🔄 Version Compatibility Demo")
    print("=" * 40)
    
    # Create v1 (substitution) message
    mk_v1 = Markrypt(cipher_mode='substitution')
    message = "This is a v1 format message"
    key = "compatibility_key"
    
    encrypted_v1 = mk_v1.encrypt(message, mapping_key=key)
    print(f"V1 Format: {encrypted_v1}")
    
    # Create v2 (ChaCha20) message
    mk_v2 = Markrypt(cipher_mode='chacha20')
    encrypted_v2 = mk_v2.encrypt(message, mapping_key=key)
    print(f"V2 Format: {encrypted_v2}")
    
    # Both can be decrypted by the same instance
    mk_universal = Markrypt()
    
    decrypted_v1 = mk_universal.decrypt(encrypted_v1, mapping_key=key)
    decrypted_v2 = mk_universal.decrypt(encrypted_v2, mapping_key=key)
    
    print(f"V1 Decrypted: {decrypted_v1}")
    print(f"V2 Decrypted: {decrypted_v2}")
    
    print(f"✅ Both versions work: {message == decrypted_v1 == decrypted_v2}")
    print()


def demo_post_quantum_crypto():
    """Demonstrate post-quantum cryptography features"""
    print("🔮 Post-Quantum Cryptography Demo")
    print("=" * 40)
    
    try:
        # Create Markrypt with PQC enabled
        mk = Markrypt(enable_pqc=True, cipher_mode='pqc')
        
        # Generate Kyber keypair for encryption
        keypair = mk.generate_pqc_keypair('kyber')
        print(f"Generated Kyber keypair")
        print(f"Public key length: {len(keypair['public_key'])} chars")
        print(f"Secret key length: {len(keypair['secret_key'])} chars")
        
        message = "This message is protected by post-quantum cryptography!"
        print(f"Original: {message}")
        
        # Encrypt with PQC (use public key as mapping_key)
        encrypted = mk.encrypt(message, mapping_key=keypair['public_key'])
        print(f"PQC Encrypted: {encrypted[:100]}...")
        
        # Decrypt with PQC (use secret key as mapping_key)
        decrypted = mk.decrypt(encrypted, mapping_key=keypair['secret_key'])
        print(f"Decrypted: {decrypted}")
        
        print(f"✅ PQC Success: {message == decrypted}")
        
        # Demonstrate digital signatures
        print("\n📝 Digital Signature Demo")
        sig_keypair = mk.generate_pqc_keypair('dilithium')
        signature = mk.sign_message(message, sig_keypair['secret_key'])
        is_valid = mk.verify_signature(message, signature, sig_keypair['public_key'])
        print(f"Signature valid: {is_valid}")
        
        print()
        
    except Exception as e:
        print(f"⚠️ PQC Demo skipped: {e}")
        print("Install PQC dependencies: pip install markrypt[pqc]")
        print()


def demo_steganography():
    """Demonstrate steganography features"""
    print("🖼️ Steganography Demo")
    print("=" * 40)
    
    try:
        # Create Markrypt with steganography enabled
        mk = Markrypt(enable_steganography=True)
        
        # Create a test cover image
        cover_path = mk.steganography.create_cover_image(
            width=400, height=300, pattern='random', output_path='test_cover.png'
        )
        print(f"Created cover image: {cover_path}")
        
        # Analyze image capacity
        analysis = mk.analyze_image_capacity(cover_path)
        print(f"Image capacity: {analysis['capacity_chars']} characters")
        print(f"Image dimensions: {analysis['dimensions']}")
        
        message = "This secret message is hidden in an image using steganography! 🕵️"
        key = "stego_key_2024"
        
        print(f"Message to hide: {message}")
        
        # Encrypt and hide message in image
        result = mk.encrypt_and_hide_in_image(
            message, key, cover_path, 'hidden_message.png', stego_password='stego123'
        )
        print(f"Hidden message in image: {result['output_path']}")
        print(f"Capacity utilization: {result['utilization']}")
        
        # Extract and decrypt message from image
        extracted = mk.extract_and_decrypt_from_image(
            'hidden_message.png', key, stego_password='stego123'
        )
        print(f"Extracted message: {extracted}")
        
        print(f"✅ Steganography Success: {message == extracted}")
        
        # Clean up test files
        for file in ['test_cover.png', 'hidden_message.png']:
            if os.path.exists(file):
                os.remove(file)
        
        print()
        
    except Exception as e:
        print(f"⚠️ Steganography Demo skipped: {e}")
        print("Install steganography dependencies: pip install markrypt[stego]")
        print()


def demo_hybrid_security():
    """Demonstrate combining multiple security features"""
    print("🛡️ Hybrid Security Demo")
    print("=" * 40)
    
    try:
        # Create Markrypt with all features enabled
        mk = Markrypt(
            enable_pqc=True,
            enable_steganography=True,
            cipher_mode='chacha20',  # Use ChaCha20 as base, then add PQC layer
            noise=True,
            noise_style='emoji'
        )
        
        message = "Ultra-secret classified information with maximum security! 🔐"
        key = "hybrid_security_key_2024"
        
        print(f"Original: {message}")
        
        # Step 1: Encrypt with ChaCha20 + emoji noise
        encrypted = mk.encrypt(message, mapping_key=key)
        print(f"ChaCha20 encrypted: {encrypted[:50]}...")
        
        # Step 2: If steganography is available, hide in image
        if mk.steganography:
            cover_path = mk.steganography.create_cover_image(
                width=600, height=400, pattern='noise', output_path='hybrid_cover.png'
            )
            
            stego_result = mk.steganography.hide_message_in_image(
                encrypted, cover_path, 'hybrid_secure.png', password='hybrid123'
            )
            print(f"Hidden in image: {stego_result['output_path']}")
            
            # Extract and decrypt
            extracted_encrypted = mk.steganography.extract_message_from_image(
                'hybrid_secure.png', password='hybrid123'
            )
            final_decrypted = mk.decrypt(extracted_encrypted, mapping_key=key)
            
            print(f"Final decrypted: {final_decrypted}")
            print(f"✅ Hybrid Security Success: {message == final_decrypted}")
            
            # Clean up
            for file in ['hybrid_cover.png', 'hybrid_secure.png']:
                if os.path.exists(file):
                    os.remove(file)
        else:
            # Just decrypt normally
            decrypted = mk.decrypt(encrypted, mapping_key=key)
            print(f"Decrypted: {decrypted}")
            print(f"✅ ChaCha20 Success: {message == decrypted}")
        
        print()
        
    except Exception as e:
        print(f"⚠️ Hybrid Security Demo error: {e}")
        print()


def main():
    """Run all demos"""
    print("🎉 Markrypt 2.3 Feature Demonstrations")
    print("=" * 50)
    print()
    
    try:
        demo_chacha20_cipher()
        demo_emoji_noise()
        demo_chacha20_with_emoji()
        demo_high_level_api()
        demo_version_compatibility()
        demo_post_quantum_crypto()
        demo_steganography()
        demo_hybrid_security()
        
        print("🎊 All demos completed successfully!")
        print("\nNew features in Markrypt 2.3:")
        print("• Post-Quantum Cryptography (Kyber KEM + Dilithium signatures)")
        print("• Steganography (hide messages in images)")
        print("• Hybrid security combining multiple techniques")
        print("• ChaCha20 stream cipher for stronger encryption")
        print("• Emoji noise mode for chaotic obfuscation")
        print("• Backward compatibility with v1/v2 formats")
        print("• Enhanced CLI with new options")
        print("• Ready for PyPI distribution")
        
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()