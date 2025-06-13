"""
ML-KEM Key Generation algorithm as specified in NIST FIPS 203.

This module implements Algorithm 18: ML-KEM.KeyGen(), which generates
the main KEM key pair for encapsulation and decapsulation.
"""

import secrets
from typing import Tuple
from pke.params import MLKEMParams
from pke.keygen import k_pke_keygen
from utils.hash_utils import H
from utils.random_utils import random_bytes

def ml_kem_keygen(params: MLKEMParams) -> Tuple[bytes, bytes]:
    """ML-KEM Key Generation (Algorithm 18).
    
    Generates a KEM key pair consisting of an encapsulation key (public key)
    and a decapsulation key (secret key). The algorithm builds upon K-PKE
    and adds additional randomness and hash values for security.
    
    Args:
        params: ML-KEM parameter set defining security level and parameters
        
    Returns:
        Tuple of (encapsulation_key, decapsulation_key) where:
        - encapsulation_key: Public key for encapsulation (384k + 32 bytes)
        - decapsulation_key: Secret key for decapsulation (768k + 96 bytes)
    """
    # Step 1: Generate random seed d for K-PKE key generation
    d = random_bytes(32)
    
    # Step 2: Generate K-PKE key pair using seed d
    ek_pke, dk_pke = k_pke_keygen(d, params)
    
    # Step 3: Generate additional random seed z for decapsulation key
    z = random_bytes(32)
    
    # Step 4: Compute hash H(ek_PKE) for implicit rejection in decapsulation
    ek_pke_hash = H(ek_pke)
    
    # Step 5: Construct encapsulation key ek = ek_PKE
    ek = ek_pke
    
    # Step 6: Construct decapsulation key dk = (dk_PKE, ek_PKE, H(ek_PKE), z)
    dk = construct_decapsulation_key(dk_pke, ek_pke, ek_pke_hash, z)
    
    return ek, dk

def construct_decapsulation_key(dk_pke: bytes, ek_pke: bytes, ek_pke_hash: bytes, z: bytes) -> bytes:
    """Construct the ML-KEM decapsulation key.
    
    The decapsulation key consists of four components concatenated together:
    1. dk_PKE: The PKE secret key (384k bytes)
    2. ek_PKE: The PKE public key (384k + 32 bytes) 
    3. H(ek_PKE): Hash of the public key (32 bytes)
    4. z: Random value for implicit rejection (32 bytes)
    
    Args:
        dk_pke: PKE secret key
        ek_pke: PKE public key  
        ek_pke_hash: Hash H(ek_PKE) of the public key
        z: Random 32-byte value
        
    Returns:
        Complete decapsulation key
    """
    dk = dk_pke + ek_pke + ek_pke_hash + z
    return dk

def parse_decapsulation_key(dk: bytes, params: MLKEMParams) -> Tuple[bytes, bytes, bytes, bytes]:
    """Parse ML-KEM decapsulation key into its components.
    
    Extracts the four components of the decapsulation key:
    dk = (dk_PKE || ek_PKE || H(ek_PKE) || z)
    
    Args:
        dk: Complete decapsulation key  
        params: Parameter set for determining component sizes
        
    Returns:
        Tuple of (dk_pke, ek_pke, ek_pke_hash, z)
        
    Raises:
        ValueError: If decapsulation key has incorrect length
    """
    expected_length = params.sk_bytes
    if len(dk) != expected_length:
        raise ValueError(f"Decapsulation key must be {expected_length} bytes, got {len(dk)}")
    
    offset = 0
    
    # Extract dk_PKE (384k bytes)
    dk_pke_len = 384 * params.k
    dk_pke = dk[offset:offset + dk_pke_len]
    offset += dk_pke_len
    
    # Extract ek_PKE (384k + 32 bytes)
    ek_pke_len = params.pk_bytes
    ek_pke = dk[offset:offset + ek_pke_len]
    offset += ek_pke_len
    
    # Extract H(ek_PKE) (32 bytes)
    ek_pke_hash = dk[offset:offset + 32]
    offset += 32
    
    # Extract z (32 bytes)
    z = dk[offset:offset + 32]
    
    return dk_pke, ek_pke, ek_pke_hash, z
