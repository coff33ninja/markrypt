"""
High-level decryption interface for Markrypt
"""

import json
from ..core import Markrypt
from ..exceptions import DecryptionError
from .utils import validate_encrypted_format, extract_metadata


class MarkryptDecryptor:
    """
    High-level decryption interface that wraps the core Markrypt functionality
    with additional convenience methods and analysis capabilities.
    """
    
    def __init__(self, **options):
        """
        Initialize decryptor with options
        
        Args:
            **options: Configuration options passed to Markrypt core
        """
        self.options = options
        self.markrypt = Markrypt(**options)
    
    def decrypt_text(self, encrypted_message, key, **kwargs):
        """
        Decrypt a text message
        
        Args:
            encrypted_message: Encrypted text to decrypt
            key: Decryption key
            **kwargs: Additional decryption options
            
        Returns:
            Decrypted text
        """
        try:
            validate_encrypted_format(encrypted_message)
            return self.markrypt.decrypt(encrypted_message, mapping_key=key, **kwargs)
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {str(e)}")
    
    def decrypt_file(self, input_file, output_file, key, **kwargs):
        """
        Decrypt a file
        
        Args:
            input_file: Path to encrypted file
            output_file: Path to output file
            key: Decryption key
            **kwargs: Additional decryption options
            
        Returns:
            Path to output file
        """
        try:
            # Try different encodings for reading encrypted files
            content = None
            for encoding in ['utf-8', 'utf-8-sig', 'latin1', 'cp1252']:
                try:
                    with open(input_file, 'r', encoding=encoding) as f:
                        content = f.read().strip()
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                raise DecryptionError("Unable to read file with any supported encoding")
            
            # Handle JSON input
            if content.startswith('{'):
                data = json.loads(content)
                if 'encrypted' in data:
                    encrypted_message = data['encrypted']
                elif 'data' in data:
                    # Reconstruct from JSON format
                    parts = [data['version'], data['metadata'], data['data'], data['salt']]
                    if data.get('hash'):
                        parts.append(data['hash'])
                    encrypted_message = ':'.join(parts)
                else:
                    raise DecryptionError("Invalid JSON format")
            else:
                encrypted_message = content
            
            decrypted = self.decrypt_text(encrypted_message, key, **kwargs)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(decrypted)
            
            return output_file
        except Exception as e:
            raise DecryptionError(f"File decryption failed: {str(e)}")
    
    def decrypt_with_analysis(self, encrypted_message, key, **kwargs):
        """
        Decrypt message and provide detailed analysis
        
        Args:
            encrypted_message: Encrypted text to decrypt
            key: Decryption key
            **kwargs: Additional decryption options
            
        Returns:
            Dictionary with decrypted text and analysis
        """
        metadata = extract_metadata(encrypted_message)
        decrypted = self.decrypt_text(encrypted_message, key, **kwargs)
        
        return {
            'decrypted': decrypted,
            'metadata': metadata,
            'analysis': {
                'original_length': len(decrypted),
                'encrypted_length': len(encrypted_message),
                'compression_ratio': len(encrypted_message) / len(decrypted) if decrypted else 0,
                'has_integrity_check': metadata.get('has_integrity', False),
                'version': metadata.get('version', 'unknown'),
                'noise_ratio': metadata.get('estimated_noise_ratio', 0),
                'metadata_encrypted': metadata.get('metadata_decoded', False)
            }
        }
    
    def batch_decrypt(self, encrypted_messages, key, **kwargs):
        """
        Decrypt multiple messages with the same key
        
        Args:
            encrypted_messages: List of encrypted messages
            key: Decryption key
            **kwargs: Additional decryption options
            
        Returns:
            Dictionary with batch results
        """
        results = []
        for i, encrypted_message in enumerate(encrypted_messages):
            try:
                decrypted = self.decrypt_text(encrypted_message, key, **kwargs)
                results.append({
                    'index': i,
                    'decrypted': decrypted,
                    'decrypted_length': len(decrypted),
                    'success': True
                })
            except Exception as e:
                results.append({
                    'index': i,
                    'error': str(e),
                    'success': False
                })
        
        return {
            'results': results,
            'total': len(encrypted_messages),
            'successful': sum(1 for r in results if r['success']),
            'failed': sum(1 for r in results if not r['success'])
        }
    
    def verify_integrity_only(self, encrypted_message, key):
        """
        Verify integrity without full decryption
        
        Args:
            encrypted_message: Encrypted text to verify
            key: Decryption key
            
        Returns:
            Boolean indicating if integrity check passed
        """
        try:
            # This will raise an exception if integrity fails
            self.decrypt_text(encrypted_message, key, verify_integrity=True)
            return True
        except Exception:
            return False
    
    def quick_decrypt(self, encrypted_message, key):
        """
        Quick decryption with minimal verification
        
        Args:
            encrypted_message: Encrypted text to decrypt
            key: Decryption key
            
        Returns:
            Decrypted text
        """
        return self.decrypt_text(encrypted_message, key, verify_integrity=False, encrypt_metadata=False)
    
    def safe_decrypt(self, encrypted_message, key):
        """
        Safe decryption with full verification and error handling
        
        Args:
            encrypted_message: Encrypted text to decrypt
            key: Decryption key
            
        Returns:
            Dictionary with decryption result and status
        """
        try:
            # First verify format
            validate_encrypted_format(encrypted_message)
            
            # Try to extract metadata
            metadata = extract_metadata(encrypted_message)
            
            # Attempt decryption
            decrypted = self.decrypt_text(encrypted_message, key, verify_integrity=True)
            
            return {
                'success': True,
                'decrypted': decrypted,
                'metadata': metadata,
                'warnings': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'decrypted': None,
                'metadata': None
            }
    
    def decrypt_from_file_safe(self, input_file, key, **kwargs):
        """
        Safely decrypt from file with multiple encoding attempts
        
        Args:
            input_file: Path to encrypted file
            key: Decryption key
            **kwargs: Additional decryption options
            
        Returns:
            Dictionary with decryption result and status
        """
        try:
            # Try different encodings for reading encrypted files
            content = None
            used_encoding = None
            for encoding in ['utf-8', 'utf-8-sig', 'latin1', 'cp1252']:
                try:
                    with open(input_file, 'r', encoding=encoding) as f:
                        content = f.read().strip()
                    used_encoding = encoding
                    break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                return {
                    'success': False,
                    'error': 'Unable to read file with any supported encoding',
                    'decrypted': None
                }
            
            # Use safe_decrypt for the actual decryption
            result = self.safe_decrypt(content, key)
            result['file_encoding'] = used_encoding
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': f"File reading failed: {str(e)}",
                'decrypted': None
            }