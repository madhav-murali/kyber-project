"""
K-PKE Decryption algorithm as specified in NIST FIPS 203.

This module implements Algorithm 17: K-PKE.Decrypt(dk_PKE, c), which
decrypts a ciphertext using the PKE secret key.
"""

import numpy as np
from typing import List
from pke.params import MLKEMParams, N, Q
from utils.poly_utils import ntt, intt, dot_product_ntt
from utils.serialization import byte_decode_12, byte_decode_du, byte_decode_dv

def k_pke_decrypt(dk_pke: bytes, c: bytes, params: MLKEMParams) -> bytes:
    """K-PKE Decryption (Algorithm 17).
    
    Decrypts a ciphertext c using the PKE secret key dk_PKE.
    This is the underlying decryption used by ML-KEM.Decaps.
    
    Args:
        dk_pke: PKE secret key s of length 384k bytes
        c: Ciphertext of length 32(d_u*k + d_v) bytes
        params: ML-KEM parameter set defining k, d_u, d_v
        
    Returns:
        Decrypted message m of exactly 32 bytes
        
    Raises:
        ValueError: If inputs have incorrect lengths
    """
    if len(dk_pke) != 384 * params.k:
        raise ValueError(f"Secret key must be {384 * params.k} bytes, got {len(dk_pke)}")
    if len(c) != params.ct_bytes:
        raise ValueError(f"Ciphertext must be {params.ct_bytes} bytes, got {len(c)}")
    
    # Step 1: Parse secret key dk_PKE = s
    s = parse_secret_key(dk_pke, params.k)
    
    # Step 2: Parse ciphertext c = (u, v)
    u_compressed, v_compressed = parse_ciphertext(c, params)
    
    # Step 3: Decompress u and v
    u = [decompress(poly, params.du) for poly in u_compressed]
    v = decompress(v_compressed, params.dv)
    
    # Step 4: Convert s and u to NTT domain
    s_hat = [ntt(poly) for poly in s]
    u_hat = [ntt(poly) for poly in u]
    
    # Step 5: Compute w = v - s^T u in NTT domain
    # First compute s^T u
    su_ntt = dot_product_ntt(s_hat, u_hat)
    
    # Convert to normal domain
    su = intt(su_ntt)
    
    # Compute w = v - su
    w = [(v[i] - su[i]) % Q for i in range(N)]
    
    # Step 6: Compress and convert w to message
    # Compress w to 1 bit per coefficient (round to closest multiple of ⌊q/2⌋)
    m = compress_to_message(w)
    
    return m

def parse_secret_key(dk_pke: bytes, k: int) -> list:
    """Parse PKE secret key into vector s.
    
    Args:
        dk_pke: Serialized secret key
        k: Vector dimension
        
    Returns:
        Secret vector s (k polynomials)
    """
    s = []
    offset = 0
    
    for i in range(k):
        poly_bytes = dk_pke[offset:offset + 384]
        poly = byte_decode_12(poly_bytes)
        s.append(poly)
        offset += 384
    
    return s

def parse_ciphertext(c: bytes, params: MLKEMParams) -> tuple:
    """Parse ciphertext into (u, v).
    
    Args:
        c: Serialized ciphertext
        params: Parameter set defining k, d_u, d_v
        
    Returns:
        Tuple of (u_compressed, v_compressed)
    """
    offset = 0
    
    # Parse compressed u vector (k polynomials)
    u_compressed = []
    u_poly_bytes = 32 * params.du  # Each compressed polynomial size
    
    for i in range(params.k):
        poly_bytes = c[offset:offset + u_poly_bytes]
        poly = byte_decode_du(poly_bytes, params.du)
        u_compressed.append(poly)
        offset += u_poly_bytes
    
    # Parse compressed v (single polynomial)
    v_poly_bytes = 32 * params.dv
    v_bytes = c[offset:offset + v_poly_bytes]
    v_compressed = byte_decode_dv(v_bytes, params.dv)
    
    return u_compressed, v_compressed

def decompress(poly_compressed: list, d: int) -> list:
    """Decompress polynomial coefficients from d bits back to Z_q.
    
    Maps coefficients from [0, 2^d) back to [0, q) using scaling.
    
    Args:
        poly_compressed: Compressed polynomial with coefficients in [0, 2^d)
        d: Number of bits used for compression
        
    Returns:
        Decompressed polynomial with coefficients in [0, q)
    """
    if d == 0:
        return [0] * len(poly_compressed)
    
    decompressed = []
    
    for coeff in poly_compressed:
        # Decompress: round(q * coeff / 2^d) mod q
        decompressed_coeff = round(Q * coeff / (1 << d)) % Q
        decompressed.append(decompressed_coeff)
    
    return decompressed

def compress_to_message(w: list) -> bytes:
    """Compress polynomial w to 32-byte message.
    
    Each coefficient is rounded to the nearest multiple of ⌊q/2⌋,
    then mapped to a bit: coefficient closer to 0 → 0, closer to ⌊q/2⌋ → 1.
    
    Args:
        w: Polynomial with 256 coefficients in Z_q
        
    Returns:
        32-byte message
    """
    q_half = Q // 2
    q_quarter = Q // 4
    
    # Extract bits from w
    bits = []
    for coeff in w:
        # Reduce coefficient modulo q to range [0, q)
        coeff = coeff % Q
        
        # Determine bit value based on distance to 0 vs q/2
        # If closer to q/2, bit = 1; if closer to 0, bit = 0
        if coeff > q_quarter and coeff < 3 * q_quarter:
            bits.append(1)
        else:
            bits.append(0)
    
    # Convert 256 bits to 32 bytes
    message = b""
    for i in range(32):
        byte_val = 0
        for j in range(8):
            bit_idx = i * 8 + j
            if bit_idx < len(bits) and bits[bit_idx]:
                byte_val |= (1 << j)
        message += bytes([byte_val])
    
    return message
