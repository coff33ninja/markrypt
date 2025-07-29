"""
Custom exceptions for Markrypt operations
"""

class MarkryptError(Exception):
    """Base exception for all Markrypt operations"""
    pass

class ValidationError(MarkryptError):
    """Raised when input validation fails"""
    pass

class DecryptionError(MarkryptError):
    """Raised when decryption operations fail"""
    pass

class IntegrityError(MarkryptError):
    """Raised when integrity verification fails"""
    pass

class ConfigurationError(MarkryptError):
    """Raised when configuration is invalid"""
    pass