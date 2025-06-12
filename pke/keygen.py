"""
K-PKE Key Generation algorithm as specified in NIST FIPS 203.

This module implements Algorithm 15: K-PKE.KeyGen(d), which generates
a key pair for the underlying public key encryption scheme.
"""

import numpy as np
from typing import Tuple
from pke.params import MLKEMParams, N, Q
from utils.hash_utils import G
from utils.poly_utils import sample_uniform_poly, sample_poly_cbd, ntt, matrix_vector_multiply_ntt
from utils.serialization import byte_encode_12

def k_pke_keygen(d: bytes, params: MLKEMParams) -> Tuple[bytes, bytes]:
    """K-PKE Key Generation (Algorithm 15).
    
    Generates a key pair for the K-PKE encryption scheme, which forms
    the foundation of ML-KEM. The algorithm samples a random matrix A,
    secret vector s, and error vector e, then computes t = As + e.
    
    Args:
        d: Random seed of exactly 32 bytes
        params: ML-KEM parameter set defining k, η₁, etc.
        
    Returns:
        Tuple of (public_key, secret_key) where:
        - public_key: Serialized (t, ρ) of length 384k + 32 bytes
        - secret_key: Serialized s of length 384k bytes
        
    Raises:
        ValueError: If d is not exactly 32 bytes
    """
    if len(d) != 32:
        raise ValueError(f"Seed d must be exactly 32 bytes, got {len(d)}")
    
    # Step 1: Expand seed using G function
    # G(d) returns 64 bytes: first 32 for ρ, next 32 for σ
    expanded = G(d)
    rho = expanded[:32]  # ρ: seed for matrix A
    sigma = expanded[32:64]  # σ: seed for secret/error vectors
    
    # Step 2: Sample matrix A ∈ R_q^{k×k} uniformly at random using ρ
    A_hat = sample_matrix_A(rho, params.k)
    
    # Step 3: Sample secret vector s from centered binomial distribution CBD_η₁
    s = sample_secret_vector(sigma, params.k, params.eta1, 0)
    
    # Step 4: Sample error vector e from centered binomial distribution CBD_η₁  
    e = sample_error_vector(sigma, params.k, params.eta1, params.k)
    
    # Step 5: Convert s and e to NTT domain
    s_hat = [ntt(poly) for poly in s]
    e_hat = [ntt(poly) for poly in e]
    
    # Step 6: Compute t = As + e in NTT domain
    # t_hat = A_hat * s_hat + e_hat
    t_hat = matrix_vector_multiply_ntt(A_hat, s_hat)
    for i in range(params.k):
        t_hat[i] = [(t_hat[i][j] + e_hat[i][j]) % Q for j in range(N)]
    
    # Step 7: Serialize public key (t, ρ) and secret key s
    pk = serialize_public_key(t_hat, rho, params.k)
    sk = serialize_secret_key(s, params.k)
    
    return pk, sk

def sample_matrix_A(rho: bytes, k: int) -> list:
    """Sample matrix A uniformly from R_q^{k×k}.
    
    Uses the XOF function with seed ρ to generate each entry A[i,j]
    by calling XOF(ρ || i || j) and then rejecting samples outside [0,q).
    
    Args:
        rho: 32-byte seed for matrix sampling
        k: Matrix dimension
        
    Returns:
        k×k matrix A in NTT domain, where each entry is a polynomial
    """
    A = []
    for i in range(k):
        row = []
        for j in range(k):
            # Sample A[i,j] using XOF(ρ || i || j)
            poly = sample_uniform_poly(rho, i, j)
            row.append(poly)
        A.append(row)
    return A

def sample_secret_vector(sigma: bytes, k: int, eta: int, offset: int) -> list:
    """Sample secret vector s from centered binomial distribution.
    
    Each component s[i] is sampled from CBD_η using PRF_η(σ, N*i + offset).
    
    Args:
        sigma: 32-byte seed for vector sampling
        k: Vector dimension
        eta: Noise parameter η for CBD
        offset: Byte offset for PRF nonce
        
    Returns:
        Vector s of k polynomials
    """
    s = []
    for i in range(k):
        # Sample s[i] using PRF_η(σ, N*i + offset)  
        poly = sample_poly_cbd(sigma, offset + i, eta)
        s.append(poly)
    return s

def sample_error_vector(sigma: bytes, k: int, eta: int, offset: int) -> list:
    """Sample error vector e from centered binomial distribution.
    
    Each component e[i] is sampled from CBD_η using PRF_η(σ, N*i + offset).
    
    Args:
        sigma: 32-byte seed for vector sampling  
        k: Vector dimension
        eta: Noise parameter η for CBD
        offset: Byte offset for PRF nonce
        
    Returns:
        Vector e of k polynomials
    """
    e = []
    for i in range(k):
        # Sample e[i] using PRF_η(σ, N*i + offset)
        poly = sample_poly_cbd(sigma, offset + i, eta)
        e.append(poly)
    return e

def serialize_public_key(t_hat: list, rho: bytes, k: int) -> bytes:
    """Serialize public key (t, ρ).
    
    The public key consists of:
    - t: k polynomials in R_q, each encoded as 384 bytes (12 bits per coefficient)
    - ρ: 32-byte seed for matrix A
    
    Args:
        t_hat: Vector t in NTT domain (k polynomials)
        rho: 32-byte matrix seed
        k: Vector dimension
        
    Returns:
        Serialized public key of length 384k + 32 bytes
    """
    pk_bytes = b""
    
    # Serialize each polynomial in t using 12-bit encoding
    for poly in t_hat:
        pk_bytes += byte_encode_12(poly)
    
    # Append ρ seed
    pk_bytes += rho
    
    return pk_bytes

def serialize_secret_key(s: list, k: int) -> bytes:
    """Serialize secret key s.
    
    Each polynomial in s is encoded using 12 bits per coefficient.
    
    Args:
        s: Secret vector (k polynomials in standard domain)
        k: Vector dimension
        
    Returns:
        Serialized secret key of length 384k bytes
    """
    sk_bytes = b""
    
    # Serialize each polynomial in s using 12-bit encoding
    for poly in s:
        sk_bytes += byte_encode_12(poly)
    
    return sk_bytes
