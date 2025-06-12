"""
ML-KEM (CRYSTALS-Kyber) Implementation according to NIST FIPS 203.

This module provides a high-level interface for the ML-KEM Key Encapsulation 
Mechanism, implementing the algorithms specified in NIST FIPS 203.

ML-KEM is a quantum-resistant key encapsulation mechanism based on the 
hardness of solving the Learning-With-Errors problem over module lattices.

Example usage:
    from kyber import ML_KEM_768
    from pke.params import ML_KEM_768 as params
    
    # Generate key pair
    ek, dk = ML_KEM_768.keygen()
    
    # Encapsulate to generate shared secret
    shared_secret, ciphertext = ML_KEM_768.encaps(ek)
    
    # Decapsulate to recover shared secret
    recovered_secret = ML_KEM_768.decaps(dk, ciphertext)
    
    assert shared_secret == recovered_secret
"""

from typing import Tuple
from pke.params import MLKEMParams, ML_KEM_512, ML_KEM_768, ML_KEM_1024
from kem.keygen import ml_kem_keygen
from kem.encaps import ml_kem_encaps, ml_kem_encaps_deterministic
from kem.decaps import ml_kem_decaps

class MLKEM:
    """ML-KEM implementation for a specific parameter set.
    
    This class provides a convenient interface for ML-KEM operations
    using a specific parameter set (security level).
    """
    
    def __init__(self, params: MLKEMParams):
        """Initialize ML-KEM with specific parameters.
        
        Args:
            params: ML-KEM parameter set defining security level
        """
        self.params = params
        
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM key pair.
        
        Generates a fresh key pair consisting of an encapsulation key
        (public key) and decapsulation key (secret key).
        
        Returns:
            Tuple of (encapsulation_key, decapsulation_key)
        """
        return ml_kem_keygen(self.params)
    
    def encaps(self, ek: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to generate shared secret and ciphertext.
        
        Takes an encapsulation key and generates a random shared secret
        along with a ciphertext that encapsulates this secret.
        
        Args:
            ek: Encapsulation key (public key)
            
        Returns:
            Tuple of (shared_secret, ciphertext)
        """
        return ml_kem_encaps(ek, self.params)
    
    def decaps(self, dk: bytes, c: bytes) -> bytes:
        """Decapsulate to recover shared secret from ciphertext.
        
        Takes a decapsulation key and ciphertext, returning the
        shared secret. Includes implicit rejection for security.
        
        Args:
            dk: Decapsulation key (secret key)
            c: Ciphertext
            
        Returns:
            32-byte shared secret
        """
        return ml_kem_decaps(dk, c, self.params)
    
    def encaps_deterministic(self, ek: bytes, m: bytes) -> Tuple[bytes, bytes]:
        """Deterministic encapsulation for testing purposes.
        
        This is a deterministic version that takes a specific message
        instead of sampling randomly. Should only be used for testing.
        
        Args:
            ek: Encapsulation key (public key)
            m: 32-byte message to encapsulate
            
        Returns:
            Tuple of (shared_secret, ciphertext)
        """
        return ml_kem_encaps_deterministic(ek, m, self.params)
    
    @property
    def name(self) -> str:
        """Get parameter set name."""
        return self.params.name
    
    @property
    def security_level(self) -> int:
        """Get NIST security category."""
        return self.params.security_category
    
    @property
    def pk_bytes(self) -> int:
        """Get public key size in bytes."""
        return self.params.pk_bytes
    
    @property
    def sk_bytes(self) -> int:
        """Get secret key size in bytes."""
        return self.params.sk_bytes
    
    @property
    def ct_bytes(self) -> int:
        """Get ciphertext size in bytes."""
        return self.params.ct_bytes
    
    @property
    def ss_bytes(self) -> int:
        """Get shared secret size in bytes."""
        return self.params.ss_bytes

# Pre-configured instances for each security level
ML_KEM_512_INSTANCE = MLKEM(ML_KEM_512)
ML_KEM_768_INSTANCE = MLKEM(ML_KEM_768)
ML_KEM_1024_INSTANCE = MLKEM(ML_KEM_1024)

# Convenient exports using the standard names
class ML_KEM_512:
    """ML-KEM-512 (Security Category 1) interface."""
    
    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        """Generate ML-KEM-512 key pair."""
        return ML_KEM_512_INSTANCE.keygen()
    
    @staticmethod
    def encaps(ek: bytes) -> Tuple[bytes, bytes]:
        """ML-KEM-512 encapsulation."""
        return ML_KEM_512_INSTANCE.encaps(ek)
    
    @staticmethod
    def decaps(dk: bytes, c: bytes) -> bytes:
        """ML-KEM-512 decapsulation."""
        return ML_KEM_512_INSTANCE.decaps(dk, c)

class ML_KEM_768:
    """ML-KEM-768 (Security Category 3) interface."""
    
    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        """Generate ML-KEM-768 key pair."""
        return ML_KEM_768_INSTANCE.keygen()
    
    @staticmethod
    def encaps(ek: bytes) -> Tuple[bytes, bytes]:
        """ML-KEM-768 encapsulation."""
        return ML_KEM_768_INSTANCE.encaps(ek)
    
    @staticmethod
    def decaps(dk: bytes, c: bytes) -> bytes:
        """ML-KEM-768 decapsulation."""
        return ML_KEM_768_INSTANCE.decaps(dk, c)

class ML_KEM_1024:
    """ML-KEM-1024 (Security Category 5) interface."""
    
    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        """Generate ML-KEM-1024 key pair."""
        return ML_KEM_1024_INSTANCE.keygen()
    
    @staticmethod
    def encaps(ek: bytes) -> Tuple[bytes, bytes]:
        """ML-KEM-1024 encapsulation."""
        return ML_KEM_1024_INSTANCE.encaps(ek)
    
    @staticmethod
    def decaps(dk: bytes, c: bytes) -> bytes:
        """ML-KEM-1024 decapsulation."""
        return ML_KEM_1024_INSTANCE.decaps(dk, c)

# Default recommended instance (Category 3 security)
default = ML_KEM_768 