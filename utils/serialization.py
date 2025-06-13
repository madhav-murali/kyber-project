"""
Serialization utilities for ML-KEM as specified in NIST FIPS 203.

This module implements the ByteEncode/ByteDecode algorithms and related
conversion functions for serializing polynomials and arrays.
"""

from typing import List
from pke.params import N, Q

def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a bit array to a byte array (Algorithm 3).
    
    Converts a bit array of length 8ℓ into a byte array of length ℓ.
    Each group of 8 bits represents a byte in little-endian order.
    
    Args:
        bits: Bit array of length multiple of 8
        
    Returns:
        Byte array
        
    Raises:
        ValueError: If bits length is not a multiple of 8
    """
    if len(bits) % 8 != 0:
        raise ValueError("Bit array length must be a multiple of 8")
    
    ell = len(bits) // 8
    B = bytearray(ell)
    
    for i in range(8 * ell):
        B[i // 8] += bits[i] * (2 ** (i % 8))
    
    return bytes(B)

def bytes_to_bits(data: bytes) -> List[int]:
    """Convert a byte array to a bit array (Algorithm 4).
    
    Converts a byte array of length ℓ into a bit array of length 8ℓ.
    Each byte is converted to 8 bits in little-endian order.
    
    Args:
        data: Input byte array
        
    Returns:
        Bit array of length 8 * len(data)
    """
    ell = len(data)
    bits = [0] * (8 * ell)
    C = list(data)  # Copy to avoid modifying input
    
    for i in range(ell):
        for j in range(8):
            bits[8 * i + j] = C[i] % 2
            C[i] = C[i] // 2
    
    return bits

def byte_encode(F: List[int], d: int) -> bytes:
    """Encode an array of d-bit integers into a byte array (Algorithm 5).
    
    Args:
        F: Array of 256 integers modulo m (where m = 2^d if d < 12, else m = q)
        d: Bit width (1 ≤ d ≤ 12)
        
    Returns:
        Byte array of length 32d
        
    Raises:
        ValueError: If d is not in valid range or F has wrong length
    """
    if not (1 <= d <= 12):
        raise ValueError("d must be in range [1, 12]")
    if len(F) != N:
        raise ValueError(f"F must have length {N}")
    
    # Determine modulus
    if d < 12:
        m = 2 ** d
        # Validate input range
        if any(x < 0 or x >= m for x in F):
            raise ValueError(f"All elements of F must be in range [0, {m-1}]")
    else:  # d == 12
        m = Q
        # Validate input range
        if any(x < 0 or x >= m for x in F):
            raise ValueError(f"All elements of F must be in range [0, {m-1}]")
    
    bits = []
    for i in range(N):
        a = F[i]
        for j in range(d):
            bits.append(a % 2)
            a = (a - bits[-1]) // 2
    
    return bits_to_bytes(bits)

def byte_decode(B: bytes, d: int) -> List[int]:
    """Decode a byte array into an array of d-bit integers (Algorithm 6).
    
    Args:
        B: Byte array of length 32d
        d: Bit width (1 ≤ d ≤ 12)
        
    Returns:
        Array of 256 integers modulo m (where m = 2^d if d < 12, else m = q)
        
    Raises:
        ValueError: If d is not in valid range or B has wrong length
    """
    if not (1 <= d <= 12):
        raise ValueError("d must be in range [1, 12]")
    if len(B) != 32 * d:
        raise ValueError(f"B must have length {32 * d}")
    
    # Determine modulus
    m = 2 ** d if d < 12 else Q
    
    bits = bytes_to_bits(B)
    F = []
    
    for i in range(N):
        value = sum(bits[i * d + j] * (2 ** j) for j in range(d))
        F.append(value % m)
    
    return F

def compress(x: int, d: int) -> int:
    """Compress an integer modulo q to d bits.
    
    Implements Compress_d: Z_q → Z_{2^d} as defined in FIPS 203.
    
    Args:
        x: Integer modulo q
        d: Number of compression bits (d < 12)
        
    Returns:
        Compressed value modulo 2^d
    """
    if d >= 12:
        raise ValueError("d must be less than 12")
    
    # Compress_d(x) = ⌊(2^d / q) · x⌋ mod 2^d
    # Use integer arithmetic to avoid floating point
    return ((x * (2 ** d) + Q // 2) // Q) % (2 ** d)

def decompress(y: int, d: int) -> int:
    """Decompress a d-bit integer to modulo q.
    
    Implements Decompress_d: Z_{2^d} → Z_q as defined in FIPS 203.
    
    Args:
        y: Compressed value modulo 2^d
        d: Number of compression bits (d < 12)
        
    Returns:
        Decompressed value modulo q
    """
    if d >= 12:
        raise ValueError("d must be less than 12")
    
    # Decompress_d(y) = ⌊(q / 2^d) · y⌋
    # Use integer arithmetic to avoid floating point
    return (y * Q + (2 ** (d - 1))) // (2 ** d)

# Legacy functions for backward compatibility
def poly_to_bytes(poly: List[int], q: int = Q, n: int = N) -> bytes:
    """Legacy function - use byte_encode instead."""
    return byte_encode(poly, 12)

def bytes_to_poly(data: bytes, q: int = Q) -> List[int]:
    """Legacy function - use byte_decode instead."""
    return byte_decode(data, 12)

def vec_to_bytes(vec: List[List[int]]) -> bytes:
    """Convert a vector of polynomials to bytes.
    
    Args:
        vec: Vector of polynomials (each polynomial is a list of coefficients)
        
    Returns:
        Concatenated byte representation
    """
    return b''.join(byte_encode(poly, 12) for poly in vec)

def bytes_to_vec(data: bytes, k: int, n: int = N) -> List[List[int]]:
    """Convert bytes to a vector of polynomials.
    
    Args:
        data: Input byte array
        k: Number of polynomials in vector
        n: Length of each polynomial (default 256)
        
    Returns:
        Vector of k polynomials
    """
    poly_len = n * 12 // 8  # 12 bits per coefficient, 8 bits per byte
    result = []
    
    for i in range(k):
        start = i * poly_len
        end = start + poly_len
        poly_bytes = data[start:end]
        poly = byte_decode(poly_bytes, 12)
        result.append(poly)
    
    return result

# Additional encoding functions for ML-KEM compression
def byte_encode_12(f: List[int]) -> bytes:
    """Encode polynomial using 12 bits per coefficient.
    
    Args:
        f: Polynomial with 256 coefficients in range [0, q)
        
    Returns:
        384-byte array representing the polynomial
    """
    return byte_encode(f, 12)

def byte_decode_12(data: bytes) -> List[int]:
    """Decode polynomial from 12 bits per coefficient.
    
    Args:
        data: 384-byte array
        
    Returns:
        Polynomial with 256 coefficients
    """
    return byte_decode(data, 12)

def byte_encode_du(f: List[int], du: int) -> bytes:
    """Encode compressed polynomial using du bits per coefficient.
    
    Args:
        f: Polynomial with 256 coefficients in range [0, 2^du)
        du: Number of bits per coefficient
        
    Returns:
        Byte array of length 32*du representing the polynomial
    """
    return byte_encode(f, du)

def byte_decode_du(data: bytes, du: int) -> List[int]:
    """Decode compressed polynomial from du bits per coefficient.
    
    Args:
        data: Byte array of length 32*du
        du: Number of bits per coefficient
        
    Returns:
        Polynomial with 256 coefficients in range [0, 2^du)
    """
    return byte_decode(data, du)

def byte_encode_dv(f: List[int], dv: int) -> bytes:
    """Encode compressed polynomial using dv bits per coefficient.
    
    Args:
        f: Polynomial with 256 coefficients in range [0, 2^dv)
        dv: Number of bits per coefficient
        
    Returns:
        Byte array of length 32*dv representing the polynomial
    """
    return byte_encode(f, dv)

def byte_decode_dv(data: bytes, dv: int) -> List[int]:
    """Decode compressed polynomial from dv bits per coefficient.
    
    Args:
        data: Byte array of length 32*dv
        dv: Number of bits per coefficient
        
    Returns:
        Polynomial with 256 coefficients in range [0, 2^dv)
    """
    return byte_decode(data, dv)