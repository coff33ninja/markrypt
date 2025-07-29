"""
Utility functions for decryption operations
"""

import base64
import json
import zlib
from ..exceptions import ValidationError, DecryptionError


def validate_encrypted_format(encrypted_message):
    """
    Validate encrypted message format
    
    Args:
        encrypted_message: Message to validate
        
    Returns:
        True if valid
        
    Raises:
        ValidationError: If format is invalid
    """
    if not encrypted_message:
        raise ValidationError("Encrypted message cannot be empty")
    
    if not encrypted_message.startswith('v1:'):
        raise ValidationError("Invalid or unsupported message format")
    
    parts = encrypted_message.split(':')
    if len(parts) < 4:
        raise ValidationError("Malformed encrypted message")
    
    return True


def extract_metadata(encrypted_message):
    """
    Extract metadata from encrypted message without decrypting
    
    Args:
        encrypted_message: Encrypted message to analyze
        
    Returns:
        Dictionary with metadata information
        
    Raises:
        DecryptionError: If metadata extraction fails
    """
    try:
        validate_encrypted_format(encrypted_message)
        parts = encrypted_message.split(':')
        
        version = parts[0]
        metadata_b64 = parts[1]
        data = parts[2]
        salt = parts[3]
        has_hash = len(parts) > 4
        
        # Try to decode metadata (basic compression only)
        try:
            metadata_bytes = base64.b64decode(metadata_b64)
            metadata = json.loads(zlib.decompress(metadata_bytes).decode('utf-8'))
            metadata_decoded = True
        except:
            metadata = None
            metadata_decoded = False
        
        return {
            'version': version,
            'has_integrity': has_hash,
            'data_length': len(data),
            'salt_length': len(salt),
            'metadata_decoded': metadata_decoded,
            'metadata_size': len(metadata_b64),
            'total_parts': len(parts),
            'estimated_noise_ratio': estimate_noise_ratio(metadata) if metadata else None
        }
    except Exception as e:
        raise DecryptionError(f"Failed to extract metadata: {str(e)}")


def estimate_noise_ratio(metadata):
    """
    Estimate the ratio of noise to real content
    
    Args:
        metadata: Decoded metadata list
        
    Returns:
        Float representing noise ratio (0.0 to 1.0)
    """
    if not metadata:
        return None
    
    noise_count = sum(1 for m in metadata if m == 1)
    total_count = len(metadata)
    
    return noise_count / total_count if total_count > 0 else 0


def analyze_encrypted_structure(encrypted_message):
    """
    Analyze the structure of an encrypted message
    
    Args:
        encrypted_message: Encrypted message to analyze
        
    Returns:
        Dictionary with structural analysis
    """
    try:
        metadata = extract_metadata(encrypted_message)
        parts = encrypted_message.split(':')
        
        return {
            'format_valid': True,
            'version': metadata['version'],
            'total_size': len(encrypted_message),
            'parts': {
                'version': len(parts[0]),
                'metadata': len(parts[1]),
                'data': len(parts[2]),
                'salt': len(parts[3]) if len(parts) > 3 else 0,
                'hash': len(parts[4]) if len(parts) > 4 else 0
            },
            'has_integrity_check': metadata['has_integrity'],
            'estimated_noise_ratio': metadata['estimated_noise_ratio'],
            'metadata_encrypted': not metadata['metadata_decoded']
        }
    except Exception as e:
        return {
            'format_valid': False,
            'error': str(e)
        }


def check_key_strength(key):
    """
    Analyze key strength and provide recommendations
    
    Args:
        key: Encryption key to analyze
        
    Returns:
        Dictionary with strength analysis
    """
    if not key:
        return {'strength': 'none', 'score': 0}
    
    score = 0
    feedback = []
    
    # Length check
    if len(key) >= 16:
        score += 3
    elif len(key) >= 8:
        score += 2
        feedback.append("Consider using a longer key (16+ characters)")
    else:
        score += 1
        feedback.append("Key is too short, use at least 8 characters")
    
    # Character variety
    has_lower = any(c.islower() for c in key)
    has_upper = any(c.isupper() for c in key)
    has_digit = any(c.isdigit() for c in key)
    has_special = any(not c.isalnum() for c in key)
    
    variety_score = sum([has_lower, has_upper, has_digit, has_special])
    score += variety_score
    
    if variety_score < 3:
        feedback.append("Use a mix of lowercase, uppercase, digits, and symbols")
    
    # Determine strength
    if score >= 6:
        strength = 'strong'
    elif score >= 4:
        strength = 'medium'
    else:
        strength = 'weak'
    
    return {
        'strength': strength,
        'score': score,
        'max_score': 7,
        'feedback': feedback,
        'character_types': {
            'lowercase': has_lower,
            'uppercase': has_upper,
            'digits': has_digit,
            'special': has_special
        }
    }


def detect_corruption(encrypted_message):
    """
    Detect potential corruption in encrypted message
    
    Args:
        encrypted_message: Message to check
        
    Returns:
        Dictionary with corruption analysis
    """
    issues = []
    
    try:
        validate_encrypted_format(encrypted_message)
    except ValidationError as e:
        issues.append(f"Format error: {e}")
    
    parts = encrypted_message.split(':')
    
    # Check for unusual part lengths
    if len(parts) >= 2:
        metadata_len = len(parts[1])
        if metadata_len < 10:
            issues.append("Metadata section unusually short")
        elif metadata_len > 1000:
            issues.append("Metadata section unusually long")
    
    if len(parts) >= 3:
        data_len = len(parts[2])
        if data_len == 0:
            issues.append("Data section is empty")
    
    if len(parts) >= 4:
        salt_len = len(parts[3])
        if salt_len != 32 and salt_len != 0:
            issues.append("Salt has unexpected length")
    
    if len(parts) >= 5:
        hash_len = len(parts[4])
        if hash_len != 64:
            issues.append("Hash has unexpected length")
    
    return {
        'corrupted': len(issues) > 0,
        'issues': issues,
        'confidence': 'high' if len(issues) == 0 else 'low'
    }


def suggest_decryption_options(encrypted_message):
    """
    Suggest optimal decryption options based on message analysis
    
    Args:
        encrypted_message: Encrypted message to analyze
        
    Returns:
        Dictionary with suggestions
    """
    try:
        structure = analyze_encrypted_structure(encrypted_message)
        suggestions = {}
        
        if structure['format_valid']:
            # Suggest metadata encryption setting
            if structure['metadata_encrypted']:
                suggestions['encrypt_metadata'] = True
            else:
                suggestions['encrypt_metadata'] = False
            
            # Suggest integrity verification
            if structure['has_integrity_check']:
                suggestions['verify_integrity'] = True
            else:
                suggestions['verify_integrity'] = False
        
        return {
            'structure': structure,
            'suggestions': suggestions
        }
    except Exception as e:
        return {
            'error': str(e),
            'suggestions': {
                'verify_integrity': True,
                'encrypt_metadata': True
            }
        }