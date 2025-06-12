"""
ML-KEM Decapsulation algorithm as specified in NIST FIPS 203.

This module implements Algorithm 20: ML-KEM.Decaps(dk, c), which recovers
the shared secret from a ciphertext using the decapsulation key.
Includes implicit rejection for protection against chosen ciphertext attacks.
"""

# Using bytes type directly instead of typing import
from pke.params import MLKEMParams
from pke.decrypt import k_pke_decrypt
from pke.encrypt import k_pke_encrypt
from kem.keygen import parse_decapsulation_key
from utils.hash_utils import H, J, G

def ml_kem_decaps(dk: bytes, c: bytes, params: MLKEMParams) -> bytes:
    """ML-KEM Decapsulation (Algorithm 20).
    
    Recovers the shared secret from a ciphertext using the decapsulation key.
    Implements implicit rejection: if decryption fails or ciphertext is invalid,
    returns a pseudorandom value derived from the secret key and ciphertext.
    
    Args:
        dk: Decapsulation key (secret key) of length 768k + 96 bytes
        c: Ciphertext of length 32(d_u*k + d_v) bytes
        params: ML-KEM parameter set defining security level and parameters
        
    Returns:
        32-byte shared secret K
        
    Raises:
        ValueError: If inputs have incorrect lengths
    """
    if len(dk) != params.sk_bytes:
        raise ValueError(f"Decapsulation key must be {params.sk_bytes} bytes, got {len(dk)}")
    if len(c) != params.ct_bytes:
        raise ValueError(f"Ciphertext must be {params.ct_bytes} bytes, got {len(c)}")
    
    # Step 1: Parse decapsulation key dk = (dk_PKE, ek_PKE, H(ek_PKE), z)
    dk_pke, ek_pke, h_ek_pke, z = parse_decapsulation_key(dk, params)
    
    # Step 2: Decrypt ciphertext to recover message
    # m' = K-PKE.Decrypt(dk_PKE, c)
    m_prime = k_pke_decrypt(dk_pke, c, params)
    
    # Step 3: Compute (K', r') = G(m' || H(ek_PKE))
    # Use the stored hash H(ek_PKE) from the decapsulation key
    g_input = m_prime + h_ek_pke
    g_output = G(g_input)  # G outputs 64 bytes
    
    K_prime = g_output[:32]   # Shared secret candidate
    r_prime = g_output[32:64] # Randomness candidate
    
    # Step 4: Re-encrypt to verify ciphertext validity
    # c' = K-PKE.Encrypt(ek_PKE, m', r')
    c_prime = k_pke_encrypt(ek_pke, m_prime, r_prime, params)
    
    # Step 5: Check if c == c' (implicit rejection)
    if constant_time_compare(c, c_prime):
        # Ciphertext is valid, return the derived shared secret
        return K_prime
    else:
        # Ciphertext is invalid, return pseudorandom value for implicit rejection
        # K = J(z || c) where z is the random value from decapsulation key
        rejection_input = z + c
        K_rejection = J(rejection_input)
        return K_rejection

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison of two byte arrays.
    
    Compares two byte arrays in constant time to prevent timing attacks.
    This is crucial for the security of the implicit rejection mechanism.
    
    Args:
        a: First byte array
        b: Second byte array
        
    Returns:
        True if arrays are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0 