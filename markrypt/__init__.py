"""
Markrypt - Markov-based text obfuscation library

A comprehensive text encryption and obfuscation library that uses Markov chains
for realistic noise generation and character substitution for encryption.
"""

from .core import Markrypt
from .exceptions import MarkryptError, ValidationError, DecryptionError, IntegrityError
from . import encrypt
from . import decrypt
from .pqc import create_pqc_instance
from .steganography import create_steganography_instance

__version__ = "2.3.0"
__author__ = "coff33ninja"
__email__ = "coff33ninja69@gmail.com"
__license__ = "MIT"

__all__ = [
    "Markrypt",
    "MarkryptError", 
    "ValidationError", 
    "DecryptionError", 
    "IntegrityError",
    "encrypt",
    "decrypt",
    "create_pqc_instance",
    "create_steganography_instance"
]