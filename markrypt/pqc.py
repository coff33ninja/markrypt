"""
Post-Quantum Cryptography module for Markrypt

Implements Kyber (KEM) and Dilithium (Digital Signatures) for quantum-resistant encryption
"""

import os
import base64
import hashlib
from .exceptions import MarkryptError

try:
    # Try to import post-quantum crypto libraries
    import kyber
    PQC_KYBER_AVAILABLE = True
except ImportError:
    PQC_KYBER_AVAILABLE = False

try:
    # Alternative implementation using pqcrypto
    from pqcrypto.kem.kyber512 import generate_keypair as kyber_generate_keypair
    from pqcrypto.kem.kyber512 import encrypt as kyber_encrypt
    from pqcrypto.kem.kyber512 import decrypt as kyber_decrypt
    from pqcrypto.sign.dilithium2 import generate_keypair as dilithium_generate_keypair
    from pqcrypto.sign.dilithium2 import sign as dilithium_sign
    from pqcrypto.sign.dilithium2 import verify as dilithium_verify
    PQC_PQCRYPTO_AVAILABLE = True
except ImportError:
    PQC_PQCRYPTO_AVAILABLE = False


class PostQuantumCrypto:
    """Post-Quantum Cryptography implementation for Markrypt"""
    
    def __init__(self):
        """Initialize PQC with available libraries"""
        self.kyber_available = PQC_KYBER_AVAILABLE or PQC_PQCRYPTO_AVAILABLE
        self.dilithium_available = PQC_PQCRYPTO_AVAILABLE
        
        if not (self.kyber_available or self.dilithium_available):
            raise MarkryptError(
                "Post-quantum cryptography requires 'pqcrypto' or 'kyber-py' libraries. "
                "Install with: pip install markrypt[pqc]"
            )
    
    def generate_kyber_keypair(self):
        """Generate Kyber KEM keypair for quantum-resistant key exchange"""
        if not self.kyber_available:
            raise MarkryptError("Kyber not available")
        
        if PQC_PQCRYPTO_AVAILABLE:
            public_key, secret_key = kyber_generate_keypair()
            return {
                'public_key': base64.b64encode(public_key).decode('utf-8'),
                'secret_key': base64.b64encode(secret_key).decode('utf-8')
            }
        else:
            raise MarkryptError("No Kyber implementation available")
    
    def kyber_encapsulate(self, public_key_b64):
        """Encapsulate a shared secret using Kyber KEM"""
        if not self.kyber_available:
            raise MarkryptError("Kyber not available")
        
        if PQC_PQCRYPTO_AVAILABLE:
            public_key = base64.b64decode(public_key_b64)
            ciphertext, shared_secret = kyber_encrypt(public_key)
            return {
                'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
                'shared_secret': base64.b64encode(shared_secret).decode('utf-8')
            }
        else:
            raise MarkryptError("No Kyber implementation available")
    
    def kyber_decapsulate(self, secret_key_b64, ciphertext_b64):
        """Decapsulate shared secret using Kyber KEM"""
        if not self.kyber_available:
            raise MarkryptError("Kyber not available")
        
        if PQC_PQCRYPTO_AVAILABLE:
            secret_key = base64.b64decode(secret_key_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            shared_secret = kyber_decrypt(secret_key, ciphertext)
            return base64.b64encode(shared_secret).decode('utf-8')
        else:
            raise MarkryptError("No Kyber implementation available")
    
    def generate_dilithium_keypair(self):
        """Generate Dilithium keypair for quantum-resistant digital signatures"""
        if not self.dilithium_available:
            raise MarkryptError("Dilithium not available")
        
        public_key, secret_key = dilithium_generate_keypair()
        return {
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'secret_key': base64.b64encode(secret_key).decode('utf-8')
        }
    
    def dilithium_sign(self, message, secret_key_b64):
        """Sign message using Dilithium"""
        if not self.dilithium_available:
            raise MarkryptError("Dilithium not available")
        
        secret_key = base64.b64decode(secret_key_b64)
        signature = dilithium_sign(message.encode('utf-8'), secret_key)
        return base64.b64encode(signature).decode('utf-8')
    
    def dilithium_verify(self, message, signature_b64, public_key_b64):
        """Verify Dilithium signature"""
        if not self.dilithium_available:
            raise MarkryptError("Dilithium not available")
        
        try:
            public_key = base64.b64decode(public_key_b64)
            signature = base64.b64decode(signature_b64)
            dilithium_verify(signature, message.encode('utf-8'), public_key)
            return True
        except Exception:
            return False
    
    def hybrid_encrypt(self, message, recipient_kyber_public_key):
        """
        Hybrid encryption: Use Kyber for key exchange, AES for data encryption
        This provides both quantum resistance and efficiency
        """
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # Generate shared secret using Kyber
        kem_result = self.kyber_encapsulate(recipient_kyber_public_key)
        shared_secret = base64.b64decode(kem_result['shared_secret'])
        
        # Derive AES key from shared secret
        aes_key = hashlib.sha256(shared_secret).digest()
        
        # Encrypt message with AES-GCM
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        return {
            'kyber_ciphertext': kem_result['ciphertext'],
            'aes_nonce': base64.b64encode(nonce).decode('utf-8'),
            'aes_ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'aes_tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    def hybrid_decrypt(self, encrypted_data, recipient_kyber_secret_key):
        """Decrypt hybrid-encrypted message"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        # Recover shared secret using Kyber
        shared_secret_b64 = self.kyber_decapsulate(
            recipient_kyber_secret_key, 
            encrypted_data['kyber_ciphertext']
        )
        shared_secret = base64.b64decode(shared_secret_b64)
        
        # Derive AES key
        aes_key = hashlib.sha256(shared_secret).digest()
        
        # Decrypt with AES-GCM
        nonce = base64.b64decode(encrypted_data['aes_nonce'])
        ciphertext = base64.b64decode(encrypted_data['aes_ciphertext'])
        tag = base64.b64decode(encrypted_data['aes_tag'])
        
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')


def create_pqc_instance():
    """Factory function to create PQC instance with error handling"""
    try:
        return PostQuantumCrypto()
    except MarkryptError as e:
        print(f"Warning: {e}")
        return None