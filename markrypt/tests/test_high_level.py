#!/usr/bin/env python3
"""
High-level API tests for Markrypt
"""

import os
import sys
import unittest
import tempfile
from pathlib import Path

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from markrypt.encrypt import MarkryptEncryptor
from markrypt.decrypt import MarkryptDecryptor
from markrypt.exceptions import MarkryptError


class TestHighLevelAPI(unittest.TestCase):
    """Test high-level Markrypt API"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        # Load test data
        self.small_text = (self.fixtures_dir / "small_text.txt").read_text(encoding='utf-8')
        self.large_text = (self.fixtures_dir / "large_text.txt").read_text(encoding='utf-8')
        self.unicode_text = (self.fixtures_dir / "unicode_text.txt").read_text(encoding='utf-8')
    
    def test_encrypt_decrypt_text(self):
        """Test basic text encryption/decryption"""
        encryptor = MarkryptEncryptor()
        decryptor = MarkryptDecryptor()
        
        encrypted = encryptor.encrypt_text(self.small_text, key='test123')
        decrypted = decryptor.decrypt_text(encrypted, key='test123')
        
        self.assertEqual(self.small_text, decrypted)
    
    def test_large_text_handling(self):
        """Test large text handling"""
        encryptor = MarkryptEncryptor(seed=42)
        decryptor = MarkryptDecryptor()
        
        encrypted = encryptor.encrypt_text(self.large_text, key='large123')
        decrypted = decryptor.decrypt_text(encrypted, key='large123')
        
        self.assertEqual(self.large_text, decrypted)
    
    def test_unicode_text_handling(self):
        """Test Unicode text handling"""
        encryptor = MarkryptEncryptor(unicode_range='full')
        decryptor = MarkryptDecryptor()
        
        encrypted = encryptor.encrypt_text(self.unicode_text, key='unicode123')
        decrypted = decryptor.decrypt_text(encrypted, key='unicode123')
        
        self.assertEqual(self.unicode_text, decrypted)
    
    def test_file_operations(self):
        """Test file encryption/decryption"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            input_file = temp_path / "input.txt"
            input_file.write_text(self.small_text)
            
            encrypted_file = temp_path / "encrypted.txt"
            decrypted_file = temp_path / "decrypted.txt"
            
            # Encrypt file
            encryptor = MarkryptEncryptor()
            encryptor.encrypt_file(str(input_file), str(encrypted_file), key='file123')
            
            # Decrypt file
            decryptor = MarkryptDecryptor()
            decryptor.decrypt_file(str(encrypted_file), str(decrypted_file), key='file123')
            
            # Verify
            decrypted_content = decrypted_file.read_text(encoding='utf-8')
            self.assertEqual(self.small_text, decrypted_content)
    
    def test_batch_operations(self):
        """Test batch encryption/decryption"""
        messages = ["Hello", "World", "Batch", "Test!", "🚀"]
        
        encryptor = MarkryptEncryptor()
        batch_result = encryptor.batch_encrypt(messages, key='batch123')
        
        self.assertEqual(batch_result['total'], len(messages))
        self.assertEqual(batch_result['successful'], len(messages))
        
        # Decrypt batch
        decryptor = MarkryptDecryptor()
        encrypted_messages = [r['encrypted'] for r in batch_result['results']]
        batch_decrypt = decryptor.batch_decrypt(encrypted_messages, key='batch123')
        
        decrypted_messages = [r['decrypted'] for r in batch_decrypt['results']]
        self.assertEqual(messages, decrypted_messages)
    
    def test_safe_decrypt(self):
        """Test safe decryption"""
        encryptor = MarkryptEncryptor()
        decryptor = MarkryptDecryptor()
        
        encrypted = encryptor.encrypt_text(self.small_text, key='safe123')
        result = decryptor.safe_decrypt(encrypted, key='safe123')
        
        self.assertTrue(result['success'])
        self.assertEqual(self.small_text, result['decrypted'])
        
        # Test with wrong key
        wrong_result = decryptor.safe_decrypt(encrypted, key='wrong123')
        self.assertFalse(wrong_result['success'])
    
    def test_decrypt_with_analysis(self):
        """Test decryption with analysis"""
        encryptor = MarkryptEncryptor()
        decryptor = MarkryptDecryptor()
        
        encrypted = encryptor.encrypt_text(self.small_text, key='analysis123')
        result = decryptor.decrypt_with_analysis(encrypted, key='analysis123')
        
        self.assertEqual(self.small_text, result['decrypted'])
        self.assertIn('analysis', result)
        self.assertIn('metadata', result)
    
    def test_quick_encrypt_decrypt(self):
        """Test quick encryption/decryption"""
        encryptor = MarkryptEncryptor()
        decryptor = MarkryptDecryptor()
        
        encrypted = encryptor.quick_encrypt(self.small_text, key='quick123')
        decrypted = decryptor.quick_decrypt(encrypted, key='quick123')
        
        self.assertEqual(self.small_text, decrypted)


if __name__ == '__main__':
    unittest.main()