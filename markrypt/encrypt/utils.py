"""
Utility functions for encryption operations
"""

import random
import string
from ..exceptions import ValidationError


def generate_key(length=16):
    """
    Generate a random encryption key
    
    Args:
        length: Length of the key to generate
        
    Returns:
        Random alphanumeric key
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def validate_options(options):
    """
    Validate encryption options
    
    Args:
        options: Dictionary of options to validate
        
    Returns:
        Validated options dictionary
        
    Raises:
        ValidationError: If options are invalid
    """
    valid_noise_styles = ['markov', 'lowercase', 'custom']
    valid_unicode_ranges = ['basic', 'full']
    
    # Set defaults
    defaults = {
        'seed': None,
        'preserve_symbols': True,
        'noise': True,
        'noise_style': 'markov',
        'custom_noise_chars': None,
        'noise_exclude': None,
        'unicode_range': 'basic',
        'unicode_blocks': None
    }
    
    # Merge with defaults
    validated = {**defaults, **options}
    
    # Validate noise style
    if validated['noise_style'] not in valid_noise_styles:
        raise ValidationError(f"Invalid noise_style. Must be one of: {valid_noise_styles}")
    
    # Validate unicode range
    if validated['unicode_range'] not in valid_unicode_ranges:
        raise ValidationError(f"Invalid unicode_range. Must be one of: {valid_unicode_ranges}")
    
    # Validate custom noise chars
    if validated['noise_style'] == 'custom' and not validated['custom_noise_chars']:
        raise ValidationError("custom_noise_chars required when noise_style is 'custom'")
    
    return validated


def estimate_encrypted_size(message_length, noise=True):
    """
    Estimate the size of encrypted message
    
    Args:
        message_length: Length of original message
        noise: Whether noise is enabled
        
    Returns:
        Estimated encrypted size in characters
    """
    base_size = message_length * 2  # Character mapping overhead
    if noise:
        base_size *= 2  # Noise doubles the size
    return base_size + 100  # Metadata overhead


def analyze_message(message):
    """
    Analyze message characteristics for encryption planning
    
    Args:
        message: Text message to analyze
        
    Returns:
        Dictionary with message analysis
    """
    return {
        'length': len(message),
        'unique_chars': len(set(message)),
        'has_unicode': any(ord(c) > 127 for c in message),
        'has_symbols': any(not c.isalnum() and not c.isspace() for c in message),
        'has_digits': any(c.isdigit() for c in message),
        'has_uppercase': any(c.isupper() for c in message),
        'has_lowercase': any(c.islower() for c in message),
        'estimated_encrypted_size': estimate_encrypted_size(len(message)),
        'estimated_encrypted_size_no_noise': estimate_encrypted_size(len(message), noise=False)
    }


def suggest_options(message):
    """
    Suggest optimal encryption options based on message analysis
    
    Args:
        message: Text message to analyze
        
    Returns:
        Dictionary with suggested options
    """
    analysis = analyze_message(message)
    suggestions = {}
    
    # Suggest unicode range
    if analysis['has_unicode']:
        suggestions['unicode_range'] = 'full'
    else:
        suggestions['unicode_range'] = 'basic'
    
    # Suggest noise settings
    if analysis['length'] < 50:
        suggestions['noise'] = True
        suggestions['noise_style'] = 'markov'
    elif analysis['length'] > 1000:
        suggestions['noise'] = False  # Large texts don't need noise
    
    # Suggest symbol preservation
    if analysis['has_symbols']:
        suggestions['preserve_symbols'] = True
    
    return {
        'analysis': analysis,
        'suggestions': suggestions,
        'reasoning': _generate_reasoning(analysis, suggestions)
    }


def _generate_reasoning(analysis, suggestions):
    """Generate human-readable reasoning for suggestions"""
    reasons = []
    
    if suggestions.get('unicode_range') == 'full':
        reasons.append("Full Unicode range suggested due to non-ASCII characters")
    
    if suggestions.get('noise') is False:
        reasons.append("Noise disabled for large text to improve performance")
    elif suggestions.get('noise_style') == 'markov':
        reasons.append("Markov noise style for natural-looking obfuscation")
    
    if suggestions.get('preserve_symbols'):
        reasons.append("Symbol preservation enabled due to special characters")
    
    return reasons