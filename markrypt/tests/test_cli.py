#!/usr/bin/env python3
"""
CLI tests for Markrypt
"""

import os
import sys
import unittest
import subprocess
import tempfile
from pathlib import Path

# Add the package to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


class TestMarkryptCLI(unittest.TestCase):
    """Test Markrypt CLI tools"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.fixtures_dir = Path(__file__).parent / "fixtures"
        self.output_dir = Path(__file__).parent / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        # Load test data
        self.small_text = (self.fixtures_dir / "small_text.txt").read_text(encoding='utf-8')
    
    def run_cli_command(self, cmd):
        """Helper to run CLI commands"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result
        except subprocess.TimeoutExpired:
            self.fail(f"Command timed out: {' '.join(cmd)}")
    
    def test_main_cli_encrypt_decrypt(self):
        """Test main CLI encrypt/decrypt"""
        # Encrypt
        encrypt_cmd = ['markrypt', 'encrypt', 'Hello CLI World!', '--key', 'clitest']
        encrypt_result = self.run_cli_command(encrypt_cmd)
        
        if encrypt_result.returncode != 0:
            self.fail(f"Encryption failed: {encrypt_result.stderr}")
        
        # Extract encrypted text
        encrypted_line = encrypt_result.stdout.strip()
        if encrypted_line.startswith('Encrypted: '):
            encrypted_text = encrypted_line[11:]  # Remove "Encrypted: " prefix
        else:
            encrypted_text = encrypted_line
        
        # Decrypt
        decrypt_cmd = ['markrypt', 'decrypt', encrypted_text, '--key', 'clitest']
        decrypt_result = self.run_cli_command(decrypt_cmd)
        
        if decrypt_result.returncode != 0:
            self.fail(f"Decryption failed: {decrypt_result.stderr}")
        
        # Extract decrypted text
        decrypted_line = decrypt_result.stdout.strip()
        if decrypted_line.startswith('Decrypted: '):
            decrypted_text = decrypted_line[11:]  # Remove "Decrypted: " prefix
        else:
            decrypted_text = decrypted_line
        
        self.assertEqual('Hello CLI World!', decrypted_text)
    
    def test_dedicated_encrypt_cli(self):
        """Test dedicated encrypt CLI"""
        cmd = ['markrypt-encrypt', 'Hello Encrypt CLI!', '--key', 'enctest']
        result = self.run_cli_command(cmd)
        
        if result.returncode != 0:
            self.fail(f"Encrypt CLI failed: {result.stderr}")
        
        self.assertIn('Encrypted:', result.stdout)
    
    def test_dedicated_decrypt_cli(self):
        """Test dedicated decrypt CLI with analysis"""
        # First encrypt something
        encrypt_cmd = ['markrypt-encrypt', 'Hello Decrypt CLI!', '--key', 'dectest']
        encrypt_result = self.run_cli_command(encrypt_cmd)
        
        if encrypt_result.returncode != 0:
            self.fail(f"Encryption failed: {encrypt_result.stderr}")
        
        # Extract encrypted text
        encrypted_line = encrypt_result.stdout.strip()
        if encrypted_line.startswith('Encrypted: '):
            encrypted_text = encrypted_line[11:]
        else:
            encrypted_text = encrypted_line
        
        # Test decrypt with analysis
        decrypt_cmd = ['markrypt-decrypt', encrypted_text, '--key', 'dectest', '--analyze']
        decrypt_result = self.run_cli_command(decrypt_cmd)
        
        if decrypt_result.returncode != 0:
            self.fail(f"Decrypt CLI failed: {decrypt_result.stderr}")
        
        self.assertIn('Hello Decrypt CLI!', decrypt_result.stdout)
    
    def test_file_cli_operations(self):
        """Test CLI file operations"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            input_file = temp_path / "cli_input.txt"
            input_file.write_text(self.small_text)
            
            # Encrypt file
            encrypt_cmd = ['markrypt-encrypt', '--input-file', str(input_file), '--key', 'filecli']
            encrypt_result = self.run_cli_command(encrypt_cmd)
            
            if encrypt_result.returncode != 0:
                self.fail(f"File encryption failed: {encrypt_result.stderr}")
            
            # Extract encrypted text
            encrypted_line = encrypt_result.stdout.strip()
            if encrypted_line.startswith('Encrypted: '):
                encrypted_text = encrypted_line[11:]
            else:
                encrypted_text = encrypted_line
            
            # Decrypt
            decrypt_cmd = ['markrypt-decrypt', encrypted_text, '--key', 'filecli']
            decrypt_result = self.run_cli_command(decrypt_cmd)
            
            if decrypt_result.returncode != 0:
                self.fail(f"File decryption failed: {decrypt_result.stderr}")
            
            # Check result contains original text
            self.assertIn(self.small_text.replace('\n', ''), decrypt_result.stdout.replace('\n', ''))


if __name__ == '__main__':
    unittest.main()