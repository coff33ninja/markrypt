#!/usr/bin/env python3
"""
Core functionality tests for Markrypt
"""

import os
import sys
import unittest
from pathlib import Path

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import markrypt
from markrypt.exceptions import MarkryptError, ValidationError, DecryptionError


class TestMarkryptCore(unittest.TestCase):
    """Test core Markrypt functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        # Load test data
        self.small_text = (self.fixtures_dir / "small_text.txt").read_text(encoding='utf-8')
        self.large_text = (self.fixtures_dir / "large_text.txt").read_text(encoding='utf-8')
        self.unicode_text = (self.fixtures_dir / "unicode_text.txt").read_text(encoding='utf-8')
        self.single_char = (self.fixtures_dir / "single_char.txt").read_text(encoding='utf-8')
    
    def test_small_text_with_noise(self):
        """Test small text encryption with noise"""
        mk = markrypt.Markrypt(noise=True, noise_style='markov')
        encrypted = mk.encrypt(self.small_text, mapping_key='test123')
        decrypted = mk.decrypt(encrypted, mapping_key='test123')
        
        self.assertEqual(self.small_text, decrypted)
        self.assertGreater(len(encrypted), len(self.small_text))
    
    def test_small_text_without_noise(self):
        """Test small text encryption without noise"""
        mk = markrypt.Markrypt(noise=False)
        encrypted = mk.encrypt(self.small_text, mapping_key='test123')
        decrypted = mk.decrypt(encrypted, mapping_key='test123')
        
        self.assertEqual(self.small_text, decrypted)
    
    def test_large_text_auto_disable_noise(self):
        """Test large text with auto-disabled noise"""
        mk = markrypt.Markrypt(noise=True, noise_style='markov')
        encrypted = mk.encrypt(self.large_text, mapping_key='lorem123')
        decrypted = mk.decrypt(encrypted, mapping_key='lorem123')
        
        self.assertEqual(self.large_text, decrypted)
    
    def test_unicode_text(self):
        """Test Unicode text encryption"""
        mk = markrypt.Markrypt(noise=True, unicode_range='full')
        encrypted = mk.encrypt(self.unicode_text, mapping_key='unicode123')
        decrypted = mk.decrypt(encrypted, mapping_key='unicode123')
        
        self.assertEqual(self.unicode_text, decrypted)
    
    def test_single_character(self):
        """Test single character encryption"""
        mk = markrypt.Markrypt(noise=True)
        encrypted = mk.encrypt(self.single_char, mapping_key='single123')
        decrypted = mk.decrypt(encrypted, mapping_key='single123')
        
        self.assertEqual(self.single_char, decrypted)
    
    def test_empty_string_validation(self):
        """Test empty string validation"""
        mk = markrypt.Markrypt()
        with self.assertRaises(ValidationError):
            mk.encrypt("", mapping_key='test123')
    
    def test_different_keys(self):
        """Test that different keys produce different results"""
        mk = markrypt.Markrypt(noise=False)
        text = "Test message"
        
        encrypted1 = mk.encrypt(text, mapping_key='key1')
        encrypted2 = mk.encrypt(text, mapping_key='key2')
        
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_wrong_key_decryption(self):
        """Test decryption with wrong key"""
        mk = markrypt.Markrypt(noise=False)
        text = "Test message"
        
        encrypted = mk.encrypt(text, mapping_key='correct_key')
        decrypted = mk.decrypt(encrypted, mapping_key='wrong_key')
        
        # Should not match original (but won't raise error)
        self.assertNotEqual(text, decrypted)
    
    def test_integrity_check(self):
        """Test integrity verification"""
        mk = markrypt.Markrypt(noise=False)
        text = "Test message with integrity"
        
        encrypted = mk.encrypt(text, mapping_key='test123', integrity_check=True)
        decrypted = mk.decrypt(encrypted, mapping_key='test123', verify_integrity=True)
        
        self.assertEqual(text, decrypted)
    
    def test_noise_styles(self):
        """Test different noise styles"""
        text = "Test noise styles"
        
        for style in ['markov', 'lowercase', 'custom']:
            with self.subTest(style=style):
                mk = markrypt.Markrypt(noise=True, noise_style=style)
                encrypted = mk.encrypt(text, mapping_key='test123')
                decrypted = mk.decrypt(encrypted, mapping_key='test123')
                
                self.assertEqual(text, decrypted)
    
    def test_preserve_symbols(self):
        """Test symbol preservation"""
        text = "Test @#$% symbols!"
        
        # With symbol preservation
        mk1 = markrypt.Markrypt(preserve_symbols=True, noise=False)
        encrypted1 = mk1.encrypt(text, mapping_key='test123')
        decrypted1 = mk1.decrypt(encrypted1, mapping_key='test123')
        
        self.assertEqual(text, decrypted1)
        
        # Without symbol preservation
        mk2 = markrypt.Markrypt(preserve_symbols=False, noise=False)
        encrypted2 = mk2.encrypt(text, mapping_key='test123')
        decrypted2 = mk2.decrypt(encrypted2, mapping_key='test123')
        
        # Results should be different
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_reproducible_with_seed(self):
        """Test reproducible results with seed"""
        text = "Test reproducibility"
        
        mk1 = markrypt.Markrypt(seed=42, noise=True)
        encrypted1 = mk1.encrypt(text, mapping_key='test123')
        
        mk2 = markrypt.Markrypt(seed=42, noise=True)
        encrypted2 = mk2.encrypt(text, mapping_key='test123')
        
        self.assertEqual(encrypted1, encrypted2)


if __name__ == '__main__':
    unittest.main()