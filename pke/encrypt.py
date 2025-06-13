"""
K-PKE Encryption algorithm as specified in NIST FIPS 203.

This module implements Algorithm 16: K-PKE.Encrypt(ek_PKE, m, r), which
encrypts a 32-byte message using the PKE public key.
"""

import numpy as np
from typing import List
from pke.params import MLKEMParams, N, Q
from utils.poly_utils import sample_poly_cbd, ntt, intt, matrix_vector_multiply_ntt, dot_product_ntt
from utils.serialization import byte_decode_12, byte_encode_du, byte_encode_dv, bits_to_bytes

def k_pke_encrypt(ek_pke: bytes, m: bytes, r: bytes, params: MLKEMParams) -> bytes:
    """K-PKE Encryption (Algorithm 16).
    
    Encrypts a 32-byte message m using the PKE public key ek_PKE and
    randomness r. This is the underlying encryption used by ML-KEM.Encaps.
    
    Args:
        ek_pke: PKE public key (t, ρ) of length 384k + 32 bytes  
        m: Message to encrypt, exactly 32 bytes
        r: Random seed for encryption, exactly 32 bytes
        params: ML-KEM parameter set defining k, η₂, d_u, d_v
        
    Returns:
        Ciphertext c of length 32(d_u*k + d_v) bytes
        
    Raises:
        ValueError: If inputs have incorrect lengths
    """
    if len(m) != 32:
        raise ValueError(f"Message m must be exactly 32 bytes, got {len(m)}")
    if len(r) != 32:
        raise ValueError(f"Randomness r must be exactly 32 bytes, got {len(r)}")
    if len(ek_pke) != params.pk_bytes:
        raise ValueError(f"Public key must be {params.pk_bytes} bytes, got {len(ek_pke)}")
    
    # Step 1: Parse public key ek_PKE = (t, ρ)
    t_hat, rho = parse_public_key(ek_pke, params.k)
    
    # Step 2: Sample matrix A from ρ (same as in key generation)
    A_hat = sample_matrix_A(rho, params.k)
    
    # Step 3: Sample error vectors from centered binomial distribution
    # r1 = CBD_η₂^k(r), r2 = CBD_η₂(r), both using different nonces
    r1 = sample_error_vector_encrypt(r, params.k, params.eta2, 0)
    r2 = sample_error_vector_encrypt(r, 1, params.eta2, params.k)[0]  # Single polynomial
    
    # Step 4: Convert to NTT domain
    r1_hat = [ntt(poly) for poly in r1]
    
    # Step 5: Compute u = A^T r1 + e1 in NTT domain
    # First compute A^T r1 (transpose of A times r1)
    u_hat = matrix_transpose_vector_multiply_ntt(A_hat, r1_hat)
    
    # Sample e1 separately (different from r1 in ML-KEM)
    e1 = sample_error_vector_encrypt(r, params.k, params.eta2, params.k)
    e1_hat = [ntt(poly) for poly in e1]
    
    for i in range(params.k):
        u_hat[i] = [(u_hat[i][j] + e1_hat[i][j]) % Q for j in range(N)]
    
    # Step 6: Convert u back to normal domain
    u = [intt(poly) for poly in u_hat]
    
    # Step 7: Compute v = t^T r1 + e2 + Decompress_1(m)
    # First compute t^T r1 in NTT domain
    v_ntt = dot_product_ntt(t_hat, r1_hat)
    
    # Convert to normal domain
    v = intt(v_ntt)
    
    # Add error e2 (r2)
    v = [(v[i] + r2[i]) % Q for i in range(N)]
    
    # Add decompressed message
    m_poly = decompress_message(m)
    v = [(v[i] + m_poly[i]) % Q for i in range(N)]
    
    # Step 8: Compress and serialize ciphertext
    # Compress u to d_u bits per coefficient  
    u_compressed = [compress(poly, params.du) for poly in u]
    
    # Compress v to d_v bits per coefficient
    v_compressed = compress(v, params.dv)
    
    # Serialize c = (Compress_du(u), Compress_dv(v))
    c = serialize_ciphertext(u_compressed, v_compressed, params)
    
    return c

def parse_public_key(ek_pke: bytes, k: int) -> tuple:
    """Parse PKE public key into (t, ρ).
    
    Args:
        ek_pke: Serialized public key
        k: Vector dimension
        
    Returns:
        Tuple of (t_hat, rho) where t_hat is already in NTT domain (as stored)
    """
    # Parse t (first 384k bytes, 12 bits per coefficient)
    # Note: t is stored in NTT domain in the public key
    t_hat = []
    offset = 0
    for i in range(k):
        poly_bytes = ek_pke[offset:offset + 384]
        poly = byte_decode_12(poly_bytes)
        t_hat.append(poly)  # t is already in NTT domain
        offset += 384
    
    # Parse ρ (last 32 bytes)
    rho = ek_pke[offset:offset + 32]
    
    return t_hat, rho

def sample_matrix_A(rho: bytes, k: int) -> list:
    """Sample matrix A uniformly from R_q^{k×k}.
    
    Reuses the same logic as in key generation.
    """
    from pke.keygen import sample_matrix_A as keygen_sample_matrix_A
    return keygen_sample_matrix_A(rho, k)

def sample_error_vector_encrypt(r: bytes, k: int, eta: int, offset: int) -> list:
    """Sample error vectors for encryption from CBD_η.
    
    Args:
        r: 32-byte randomness seed
        k: Vector dimension
        eta: Noise parameter η for CBD
        offset: Byte offset for PRF nonce
        
    Returns:
        Vector of k polynomials from CBD_η
    """
    from pke.keygen import sample_error_vector
    return sample_error_vector(r, k, eta, offset)

def matrix_transpose_vector_multiply_ntt(A_hat: list, r1_hat: list) -> list:
    """Compute A^T * r1 in NTT domain.
    
    Args:
        A_hat: k×k matrix A in NTT domain
        r1_hat: Vector r1 in NTT domain
        
    Returns:
        Vector A^T * r1 in NTT domain
    """
    from utils.poly_utils import multiply_ntts, add_poly
    
    k = len(r1_hat)
    result = []
    
    for j in range(k):
        # Compute j-th component: sum_i A[i][j] * r1[i]
        poly_result = [0] * N
        for i in range(k):
            # Proper polynomial multiplication in NTT domain
            product = multiply_ntts(A_hat[i][j], r1_hat[i])
            poly_result = add_poly(poly_result, product, Q)
        result.append(poly_result)
    
    return result

def decompress_message(m: bytes) -> list:
    """Decompress 32-byte message to polynomial with coefficients in {0, ⌊q/2⌋}.
    
    Args:
        m: 32-byte message
        
    Returns:
        Polynomial with 256 coefficients
    """
    # Convert message bytes to bits
    m_bits = []
    for byte in m:
        for i in range(8):
            m_bits.append((byte >> i) & 1)
    
    # Each bit becomes a coefficient: 0 → 0, 1 → ⌊q/2⌋
    q_half = Q // 2
    poly = []
    for i in range(N):
        poly.append(m_bits[i] * q_half)
    
    return poly

def compress(poly: list, d: int) -> list:
    """Compress polynomial coefficients to d bits.
    
    Maps coefficients from [0, q) to [0, 2^d) using rounding.
    
    Args:
        poly: Polynomial with coefficients in [0, q)
        d: Number of bits for compression
        
    Returns:
        Compressed polynomial with coefficients in [0, 2^d)
    """
    if d == 0:
        return [0] * len(poly)
    
    compressed = []
    divisor = Q // (1 << d)  # q / 2^d
    
    for coeff in poly:
        # Round(2^d * coeff / q) mod 2^d
        compressed_coeff = round((1 << d) * coeff / Q) % (1 << d)
        compressed.append(compressed_coeff)
    
    return compressed

def serialize_ciphertext(u_compressed: list, v_compressed: list, params: MLKEMParams) -> bytes:
    """Serialize compressed ciphertext (u, v).
    
    Args:
        u_compressed: k compressed polynomials for u
        v_compressed: Single compressed polynomial for v  
        params: Parameter set defining d_u, d_v
        
    Returns:
        Serialized ciphertext
    """
    c_bytes = b""
    
    # Serialize compressed u vector
    for poly in u_compressed:
        c_bytes += byte_encode_du(poly, params.du)
    
    # Serialize compressed v
    c_bytes += byte_encode_dv(v_compressed, params.dv)
    
    return c_bytes
