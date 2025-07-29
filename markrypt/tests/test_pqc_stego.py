#!/usr/bin/env python3
"""
Tests for post-quantum cryptography and steganography features
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import markrypt
from markrypt.exceptions import MarkryptError


class TestPostQuantumCrypto(unittest.TestCase):
    """Test post-quantum cryptography features"""
    
    def setUp(self):
        """Set up test fixtures"""
        try:
            self.mk = markrypt.Markrypt(enable_pqc=True, cipher_mode='pqc')
            self.pqc_available = True
        except MarkryptError:
            self.pqc_available = False
            self.skipTest("Post-quantum cryptography dependencies not available")
    
    def test_kyber_keypair_generation(self):
        """Test Kyber keypair generation"""
        if not self.pqc_available:
            self.skipTest("PQC not available")
        
        keypair = self.mk.generate_pqc_keypair('kyber')
        
        self.assertIn('public_key', keypair)
        self.assertIn('secret_key', keypair)
        self.assertIsInstance(keypair['public_key'], str)
        self.assertIsInstance(keypair['secret_key'], str)
        self.assertGreater(len(keypair['public_key']), 100)
        self.assertGreater(len(keypair['secret_key']), 100)
    
    def test_dilithium_keypair_generation(self):
        """Test Dilithium keypair generation"""
        if not self.pqc_available:
            self.skipTest("PQC not available")
        
        keypair = self.mk.generate_pqc_keypair('dilithium')
        
        self.assertIn('public_key', keypair)
        self.assertIn('secret_key', keypair)
        self.assertIsInstance(keypair['public_key'], str)
        self.assertIsInstance(keypair['secret_key'], str)
    
    def test_pqc_encryption_decryption(self):
        """Test PQC encryption and decryption"""
        if not self.pqc_available:
            self.skipTest("PQC not available")
        
        message = "This is a test message for post-quantum cryptography!"
        keypair = self.mk.generate_pqc_keypair('kyber')
        
        # Encrypt with public key
        encrypted = self.mk.encrypt(message, mapping_key=keypair['public_key'])
        
        # Decrypt with secret key
        decrypted = self.mk.decrypt(encrypted, mapping_key=keypair['secret_key'])
        
        self.assertEqual(message, decrypted)
        self.assertTrue(encrypted.startswith('v3:pqc:'))
    
    def test_digital_signatures(self):
        """Test Dilithium digital signatures"""
        if not self.pqc_available:
            self.skipTest("PQC not available")
        
        message = "Document to be signed"
        keypair = self.mk.generate_pqc_keypair('dilithium')
        
        # Sign message
        signature = self.mk.sign_message(message, keypair['secret_key'])
        
        # Verify signature
        is_valid = self.mk.verify_signature(message, signature, keypair['public_key'])
        self.assertTrue(is_valid)
        
        # Test with wrong message
        wrong_valid = self.mk.verify_signature("Wrong message", signature, keypair['public_key'])
        self.assertFalse(wrong_valid)
    
    def test_pqc_with_integrity_check(self):
        """Test PQC with integrity verification"""
        if not self.pqc_available:
            self.skipTest("PQC not available")
        
        message = "Test message with integrity check"
        keypair = self.mk.generate_pqc_keypair('kyber')
        
        encrypted = self.mk.encrypt(message, mapping_key=keypair['public_key'], integrity_check=True)
        decrypted = self.mk.decrypt(encrypted, mapping_key=keypair['secret_key'], verify_integrity=True)
        
        self.assertEqual(message, decrypted)


class TestSteganography(unittest.TestCase):
    """Test steganography features"""
    
    def setUp(self):
        """Set up test fixtures"""
        try:
            self.mk = markrypt.Markrypt(enable_steganography=True)
            self.stego_available = True
        except MarkryptError:
            self.stego_available = False
            self.skipTest("Steganography dependencies not available")
        
        self.temp_dir = tempfile.mkdtemp()
        self.cover_image = os.path.join(self.temp_dir, 'cover.png')
        self.output_image = os.path.join(self.temp_dir, 'output.png')
    
    def tearDown(self):
        """Clean up test files"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_create_cover_image(self):
        """Test cover image creation"""
        if not self.stego_available:
            self.skipTest("Steganography not available")
        
        created_path = self.mk.steganography.create_cover_image(
            width=200, height=150, pattern='random', output_path=self.cover_image
        )
        
        self.assertEqual(created_path, self.cover_image)
        self.assertTrue(os.path.exists(self.cover_image))
        
        # Check file size is reasonable
        file_size = os.path.getsize(self.cover_image)
        self.assertGreater(file_size, 1000)  # At least 1KB
    
    def test_image_capacity_analysis(self):
        """Test image capacity analysis"""
        if not self.stego_available:
            self.skipTest("Steganography not available")
        
        # Create test image
        self.mk.steganography.create_cover_image(
            width=100, height=100, pattern='random', output_path=self.cover_image
        )
        
        analysis = self.mk.analyze_image_capacity(self.cover_image)
        
        self.assertIn('capacity_chars', analysis)
        self.assertIn('dimensions', analysis)
        self.assertIn('total_pixels', analysis)
        self.assertEqual(analysis['total_pixels'], 10000)  # 100x100
        self.assertGreater(analysis['capacity_chars'], 1000)  # Should be able to hide >1KB
    
    def test_encrypt_and_hide_in_image(self):
        """Test encrypting and hiding message in image"""
        if not self.stego_available:
            self.skipTest("Steganography not available")
        
        # Create cover image
        self.mk.steganography.create_cover_image(
            width=200, height=200, pattern='random', output_path=self.cover_image
        )
        
        message = "This is a secret message hidden in an image!"
        key = "test_key_123"
        
        # Encrypt and hide
        result = self.mk.encrypt_and_hide_in_image(
            message, key, self.cover_image, self.output_image
        )
        
        self.assertTrue(result['success'])
        self.assertTrue(os.path.exists(self.output_image))
        self.assertEqual(result['original_message_length'], len(message))
        
        # Extract and decrypt
        extracted = self.mk.extract_and_decrypt_from_image(self.output_image, key)
        
        self.assertEqual(message, extracted)
    
    def test_steganography_with_password(self):
        """Test steganography with password protection"""
        if not self.stego_available:
            self.skipTest("Steganography not available")
        
        # Create cover image
        self.mk.steganography.create_cover_image(
            width=150, height=150, pattern='gradient', output_path=self.cover_image
        )
        
        message = "Password-protected secret message"
        key = "encryption_key"
        stego_password = "stego_password_123"
        
        # Encrypt and hide with password
        result = self.mk.encrypt_and_hide_in_image(
            message, key, self.cover_image, self.output_image, 
            stego_password=stego_password
        )
        
        self.assertTrue(result['success'])
        
        # Extract with correct password
        extracted = self.mk.extract_and_decrypt_from_image(
            self.output_image, key, stego_password=stego_password
        )
        self.assertEqual(message, extracted)
        
        # Try to extract without password (should fail)
        with self.assertRaises(MarkryptError):
            self.mk.extract_and_decrypt_from_image(self.output_image, key)
    
    def test_message_too_large_for_image(self):
        """Test handling of message too large for image capacity"""
        if not self.stego_available:
            self.skipTest("Steganography not available")
        
        # Create very small image
        self.mk.steganography.create_cover_image(
            width=10, height=10, pattern='random', output_path=self.cover_image
        )
        
        # Try to hide large message
        large_message = "x" * 10000  # Much larger than 10x10 image can hold
        key = "test_key"
        
        with self.assertRaises(MarkryptError):
            self.mk.encrypt_and_hide_in_image(
                large_message, key, self.cover_image, self.output_image
            )


class TestHybridFeatures(unittest.TestCase):
    """Test combining multiple security features"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test files"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_chacha20_with_steganography(self):
        """Test ChaCha20 encryption combined with steganography"""
        try:
            mk = markrypt.Markrypt(
                enable_steganography=True,
                cipher_mode='chacha20'
            )
        except MarkryptError:
            self.skipTest("Required dependencies not available")
        
        cover_image = os.path.join(self.temp_dir, 'cover.png')
        output_image = os.path.join(self.temp_dir, 'output.png')
        
        # Create cover image
        mk.steganography.create_cover_image(
            width=300, height=200, pattern='noise', output_path=cover_image
        )
        
        message = "ChaCha20 encrypted message hidden in image"
        key = "chacha20_key"
        
        # Encrypt with ChaCha20 and hide in image
        result = mk.encrypt_and_hide_in_image(message, key, cover_image, output_image)
        
        self.assertTrue(result['success'])
        
        # Extract and decrypt
        extracted = mk.extract_and_decrypt_from_image(output_image, key)
        
        self.assertEqual(message, extracted)
    
    def test_version_compatibility(self):
        """Test that new versions are properly handled"""
        mk = markrypt.Markrypt()
        
        # Test v1 format (substitution)
        mk_v1 = markrypt.Markrypt(cipher_mode='substitution')
        message = "Version compatibility test"
        key = "test_key"
        
        encrypted_v1 = mk_v1.encrypt(message, mapping_key=key)
        self.assertTrue(encrypted_v1.startswith('v1:'))
        
        decrypted_v1 = mk.decrypt(encrypted_v1, mapping_key=key)
        self.assertEqual(message, decrypted_v1)
        
        # Test v2 format (ChaCha20)
        try:
            mk_v2 = markrypt.Markrypt(cipher_mode='chacha20')
            encrypted_v2 = mk_v2.encrypt(message, mapping_key=key)
            self.assertTrue(encrypted_v2.startswith('v2:chacha20:'))
            
            decrypted_v2 = mk.decrypt(encrypted_v2, mapping_key=key)
            self.assertEqual(message, decrypted_v2)
        except MarkryptError:
            pass  # ChaCha20 requires cryptography library


if __name__ == '__main__':
    unittest.main()