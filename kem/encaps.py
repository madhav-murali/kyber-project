"""
ML-KEM Encapsulation algorithm as specified in NIST FIPS 203.

This module implements Algorithm 19: ML-KEM.Encaps(ek), which generates
a shared secret and corresponding ciphertext using the encapsulation key.
"""

from typing import Tuple
from pke.params import MLKEMParams
from pke.encrypt import k_pke_encrypt
from utils.hash_utils import H, J, G
from utils.random_utils import random_bytes

def ml_kem_encaps(ek: bytes, params: MLKEMParams) -> Tuple[bytes, bytes]:
    """ML-KEM Encapsulation (Algorithm 19).
    
    Generates a shared secret and ciphertext using the encapsulation key.
    The algorithm samples a random message, derives keys using hash functions,
    encrypts the message using K-PKE, and computes the shared secret.
    
    Args:
        ek: Encapsulation key (public key) of length 384k + 32 bytes
        params: ML-KEM parameter set defining security level and parameters
        
    Returns:
        Tuple of (shared_secret, ciphertext) where:
        - shared_secret: 32-byte shared secret K
        - ciphertext: Ciphertext of length 32(d_u*k + d_v) bytes
        
    Raises:
        ValueError: If encapsulation key has incorrect length
    """
    if len(ek) != params.pk_bytes:
        raise ValueError(f"Encapsulation key must be {params.pk_bytes} bytes, got {len(ek)}")
    
    # Step 1: Sample random message m
    m = random_bytes(32)
    
    # Step 2: Compute (K, r) = G(m || H(ek))
    # First compute H(ek)
    ek_hash = H(ek)
    
    # Concatenate m || H(ek) and apply G
    g_input = m + ek_hash
    g_output = G(g_input)  # G outputs 64 bytes
    
    # Split G output into K (first 32 bytes) and r (last 32 bytes)
    K = g_output[:32]   # Shared secret candidate
    r = g_output[32:64] # Randomness for encryption
    
    # Step 3: Encrypt message using K-PKE with randomness r
    # c = K-PKE.Encrypt(ek, m, r)
    c = k_pke_encrypt(ek, m, r, params)
    
    # Step 4: Return shared secret K and ciphertext c
    return K, c

def ml_kem_encaps_deterministic(ek: bytes, m: bytes, params: MLKEMParams) -> Tuple[bytes, bytes]:
    """Deterministic ML-KEM Encapsulation for testing purposes.
    
    This is a deterministic version of encapsulation that takes the message m
    as input instead of sampling it randomly. This is useful for testing
    and verification but should not be used in production.
    
    Args:
        ek: Encapsulation key (public key)
        m: 32-byte message to encapsulate
        params: ML-KEM parameter set
        
    Returns:
        Tuple of (shared_secret, ciphertext)
        
    Raises:
        ValueError: If inputs have incorrect lengths
    """
    if len(ek) != params.pk_bytes:
        raise ValueError(f"Encapsulation key must be {params.pk_bytes} bytes, got {len(ek)}")
    if len(m) != 32:
        raise ValueError(f"Message must be exactly 32 bytes, got {len(m)}")
    
    # Step 1: Compute (K, r) = G(m || H(ek))
    ek_hash = H(ek)
    g_input = m + ek_hash
    g_output = G(g_input)
    
    K = g_output[:32]   # Shared secret
    r = g_output[32:64] # Randomness for encryption
    
    # Step 2: Encrypt message
    c = k_pke_encrypt(ek, m, r, params)
    
    return K, c 