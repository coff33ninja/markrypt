"""
High-level encryption interface for Markrypt
"""

import json
from ..core import Markrypt
from ..exceptions import MarkryptError
from .utils import generate_key, validate_options


class MarkryptEncryptor:
    """
    High-level encryption interface that wraps the core Markrypt functionality
    with additional convenience methods and batch processing capabilities.
    """
    
    def __init__(self, **options):
        """
        Initialize encryptor with options
        
        Args:
            **options: Configuration options passed to Markrypt core
        """
        self.options = validate_options(options)
        self.markrypt = Markrypt(**self.options)
    
    def encrypt_text(self, message, key=None, **kwargs):
        """
        Encrypt a text message
        
        Args:
            message: Text to encrypt
            key: Encryption key (generated if None)
            **kwargs: Additional encryption options
            
        Returns:
            Encrypted text or JSON object
        """
        if not key:
            key = generate_key()
            print(f"Generated key: {key} (save this for decryption!)")
        
        try:
            return self.markrypt.encrypt(message, mapping_key=key, **kwargs)
        except Exception as e:
            raise MarkryptError(f"Encryption failed: {str(e)}")
    
    def encrypt_file(self, input_file, output_file, key=None, **kwargs):
        """
        Encrypt a file
        
        Args:
            input_file: Path to input file
            output_file: Path to output file
            key: Encryption key
            **kwargs: Additional encryption options
            
        Returns:
            Path to output file
        """
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            encrypted = self.encrypt_text(content, key, **kwargs)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                if kwargs.get('json_output', False):
                    json.dump(encrypted, f, indent=2)
                else:
                    f.write(encrypted)
            
            return output_file
        except Exception as e:
            raise MarkryptError(f"File encryption failed: {str(e)}")
    
    def encrypt_with_qr(self, message, key=None, qr_file="encrypted.png", **kwargs):
        """
        Encrypt message and generate QR code
        
        Args:
            message: Text to encrypt
            key: Encryption key
            qr_file: Path for QR code image
            **kwargs: Additional encryption options
            
        Returns:
            Encrypted text
        """
        kwargs['qr_file'] = qr_file
        return self.encrypt_text(message, key, **kwargs)
    
    def batch_encrypt(self, messages, key=None, **kwargs):
        """
        Encrypt multiple messages with the same key
        
        Args:
            messages: List of messages to encrypt
            key: Encryption key (generated if None)
            **kwargs: Additional encryption options
            
        Returns:
            Dictionary with batch results
        """
        if not key:
            key = generate_key()
            print(f"Generated key for batch: {key}")
        
        results = []
        for i, message in enumerate(messages):
            try:
                encrypted = self.encrypt_text(message, key, **kwargs)
                results.append({
                    'index': i,
                    'original_length': len(message),
                    'encrypted': encrypted,
                    'success': True
                })
            except Exception as e:
                results.append({
                    'index': i,
                    'error': str(e),
                    'success': False
                })
        
        return {
            'key': key,
            'results': results,
            'total': len(messages),
            'successful': sum(1 for r in results if r['success'])
        }
    
    def quick_encrypt(self, message, key=None):
        """
        Quick encryption with default settings
        
        Args:
            message: Text to encrypt
            key: Encryption key
            
        Returns:
            Encrypted text
        """
        return self.encrypt_text(message, key, integrity_check=True, encrypt_metadata=False)