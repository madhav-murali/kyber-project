"""
Polynomial utilities for ML-KEM as specified in NIST FIPS 203.

This module implements the core polynomial operations including:
- Number-Theoretic Transform (NTT) and inverse NTT
- Polynomial sampling algorithms
- NTT domain multiplication
- Basic polynomial arithmetic
"""

import numpy as np
from typing import List, Tuple
from pke.params import N, Q, ZETA
from utils.hash_utils import XOF, PRF
from utils.serialization import bytes_to_bits

def bit_rev_7(x: int) -> int:
    """Compute 7-bit bit reversal as defined in FIPS 203.
    
    Args:
        x: Integer in range [0, 127]
        
    Returns:
        Bit-reversed integer
    """
    result = 0
    for i in range(7):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result

def mod_pow(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

# Precompute NTT twiddle factors
def _precompute_ntt_factors():
    """Precompute NTT twiddle factors for efficient computation."""
    # ζ^BitRev_7(i) mod q for i = 1, ..., 127
    factors = [0] * 128
    for i in range(128):
        bit_rev_i = bit_rev_7(i)
        factors[i] = mod_pow(ZETA, bit_rev_i, Q)
    return factors

def _precompute_base_case_factors():
    """Precompute factors for base case multiplication."""
    # ζ^(2*BitRev_7(i) + 1) mod q for i = 0, ..., 127
    factors = [0] * 128
    for i in range(128):
        bit_rev_i = bit_rev_7(i)
        exp = (2 * bit_rev_i + 1) % (2 * N)
        factors[i] = mod_pow(ZETA, exp, Q)
    return factors

# Precomputed factors
NTT_FACTORS = _precompute_ntt_factors()
BASE_CASE_FACTORS = _precompute_base_case_factors()

def ntt(f: List[int]) -> List[int]:
    """Number-Theoretic Transform (Algorithm 9).
    
    Computes the NTT representation of polynomial f ∈ R_q.
    
    Args:
        f: Polynomial coefficients (length 256)
        
    Returns:
        NTT representation as coefficient array
    """
    if len(f) != N:
        raise ValueError(f"Input must have length {N}")
    
    # Work on a copy to avoid modifying input
    f_hat = f[:]
    k = 1
    
    length = 128
    while length >= 2:
        start = 0
        while start < N:
            zeta = NTT_FACTORS[k]
            k += 1
            
            for j in range(start, start + length):
                t = (zeta * f_hat[j + length]) % Q
                f_hat[j + length] = (f_hat[j] - t) % Q
                f_hat[j] = (f_hat[j] + t) % Q
            
            start += 2 * length
        length //= 2
    
    return f_hat

def ntt_inverse(f_hat: List[int]) -> List[int]:
    """Inverse Number-Theoretic Transform (Algorithm 10).
    
    Computes the polynomial f ∈ R_q from its NTT representation.
    
    Args:
        f_hat: NTT representation (length 256)
        
    Returns:
        Polynomial coefficients
    """
    if len(f_hat) != N:
        raise ValueError(f"Input must have length {N}")
    
    # Work on a copy to avoid modifying input
    f = f_hat[:]
    k = 127
    
    length = 2
    while length <= 128:
        start = 0
        while start < N:
            zeta = NTT_FACTORS[k]
            k -= 1
            
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % Q
                f[j + length] = (zeta * (f[j + length] - t)) % Q
            
            start += 2 * length
        length *= 2
    
    # Multiply by n^-1 = 128^-1 = 3303 mod q
    n_inv = 3303  # 128^-1 mod 3329
    for i in range(N):
        f[i] = (f[i] * n_inv) % Q
    
    return f

def base_case_multiply(a0: int, a1: int, b0: int, b1: int, gamma: int) -> Tuple[int, int]:
    """Base case multiplication for NTT (Algorithm 12).
    
    Computes (a0 + a1*X) * (b0 + b1*X) mod (X^2 - gamma).
    
    Args:
        a0, a1: Coefficients of first polynomial
        b0, b1: Coefficients of second polynomial  
        gamma: Quadratic modulus parameter
        
    Returns:
        Tuple (c0, c1) of result coefficients
    """
    c0 = (a0 * b0 + a1 * b1 * gamma) % Q
    c1 = (a0 * b1 + a1 * b0) % Q
    return c0, c1

def multiply_ntts(f_hat: List[int], g_hat: List[int]) -> List[int]:
    """Multiply two polynomials in NTT domain (Algorithm 11).
    
    Args:
        f_hat: First NTT representation
        g_hat: Second NTT representation
        
    Returns:
        Product in NTT domain
    """
    if len(f_hat) != N or len(g_hat) != N:
        raise ValueError(f"Inputs must have length {N}")
    
    h_hat = [0] * N
    
    for i in range(128):
        gamma = BASE_CASE_FACTORS[i]
        c0, c1 = base_case_multiply(
            f_hat[2*i], f_hat[2*i + 1],
            g_hat[2*i], g_hat[2*i + 1],
            gamma
        )
        h_hat[2*i] = c0
        h_hat[2*i + 1] = c1
    
    return h_hat

def sample_ntt(B: bytes) -> List[int]:
    """Sample polynomial uniformly from NTT domain (Algorithm 7).
    
    Takes a 34-byte input (32-byte seed + 2 indices) and generates
    a uniformly random element of T_q using rejection sampling.
    
    Args:
        B: 34-byte input (seed || i || j)
        
    Returns:
        Uniform random element in NTT domain
    """
    if len(B) != 34:
        raise ValueError("Input must be 34 bytes")
    
    # Extract seed and indices
    rho = B[:32]
    i = B[32]
    j = B[33]
    
    # Initialize XOF
    xof = XOF(rho, i, j)
    
    a_hat = [0] * N
    idx = 0
    
    while idx < N:
        # Get 3 bytes from XOF
        C = xof.squeeze(3)
        
        # Extract two 12-bit values
        d1 = C[0] + 256 * (C[1] % 16)  # 0 ≤ d1 < 2^12
        d2 = (C[1] // 16) + 16 * C[2]  # 0 ≤ d2 < 2^12
        
        # Rejection sampling
        if d1 < Q:
            a_hat[idx] = d1
            idx += 1
        
        if d2 < Q and idx < N:
            a_hat[idx] = d2
            idx += 1
    
    return a_hat

def sample_poly_cbd(sigma: bytes, nonce: int, eta: int) -> List[int]:
    """Sample polynomial from centered binomial distribution (Algorithm 8).
    
    This function uses PRF_η(σ, N) to generate the required random bytes,
    then samples from the centered binomial distribution.
    
    Args:
        sigma: 32-byte seed
        nonce: Nonce value for PRF
        eta: Distribution parameter (2 or 3)
        
    Returns:
        Polynomial with coefficients from CBD
    """
    if eta not in {2, 3}:
        raise ValueError("eta must be 2 or 3")
    if len(sigma) != 32:
        raise ValueError("sigma must be 32 bytes")
    
    # Generate random bytes using PRF_η(σ, nonce)
    B = PRF(eta, sigma, bytes([nonce]))
    
    bits = bytes_to_bits(B)
    f = [0] * N
    
    for i in range(N):
        # Sum eta bits for positive part
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        # Sum eta bits for negative part  
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        # Centered binomial sample
        f[i] = (x - y) % Q
    
    return f

def sample_poly_cbd_raw(B: bytes, eta: int) -> List[int]:
    """Sample polynomial from CBD using raw bytes (legacy function).
    
    Args:
        B: Input byte array of length 64*eta
        eta: Distribution parameter (2 or 3)
        
    Returns:
        Polynomial with coefficients from CBD
    """
    if eta not in {2, 3}:
        raise ValueError("eta must be 2 or 3")
    if len(B) != 64 * eta:
        raise ValueError(f"Input must be {64 * eta} bytes")
    
    bits = bytes_to_bits(B)
    f = [0] * N
    
    for i in range(N):
        # Sum eta bits for positive part
        x = sum(bits[2 * i * eta + j] for j in range(eta))
        # Sum eta bits for negative part  
        y = sum(bits[2 * i * eta + eta + j] for j in range(eta))
        # Centered binomial sample
        f[i] = (x - y) % Q
    
    return f

# Legacy polynomial operations for backward compatibility
def sample_poly(n: int = N, q: int = Q) -> List[int]:
    """Sample a random polynomial (legacy function)."""
    return [np.random.randint(0, q) for _ in range(n)]

def add_poly(a: List[int], b: List[int], q: int = Q) -> List[int]:
    """Add two polynomials."""
    if len(a) != len(b):
        raise ValueError("Polynomials must have same length")
    return [(x + y) % q for x, y in zip(a, b)]

def sub_poly(a: List[int], b: List[int], q: int = Q) -> List[int]:
    """Subtract two polynomials."""
    if len(a) != len(b):
        raise ValueError("Polynomials must have same length")
    return [(x - y) % q for x, y in zip(a, b)]

def mul_poly(a: List[int], b: List[int], q: int = Q) -> List[int]:
    """Multiply two polynomials using NTT."""
    if len(a) != N or len(b) != N:
        raise ValueError(f"Polynomials must have length {N}")
    
    # Convert to NTT domain
    a_hat = ntt(a)
    b_hat = ntt(b)
    
    # Multiply in NTT domain
    c_hat = multiply_ntts(a_hat, b_hat)
    
    # Convert back to coefficient representation
    return ntt_inverse(c_hat)

def scalar_mul_poly(scalar: int, poly: List[int], q: int = Q) -> List[int]:
    """Multiply polynomial by scalar."""
    return [(scalar * coeff) % q for coeff in poly]

# Vector operations
def add_poly_vec(a: List[List[int]], b: List[List[int]], q: int = Q) -> List[List[int]]:
    """Add two polynomial vectors."""
    if len(a) != len(b):
        raise ValueError("Vectors must have same length")
    return [add_poly(a[i], b[i], q) for i in range(len(a))]

def scalar_mul_poly_vec(scalar: int, vec: List[List[int]], q: int = Q) -> List[List[int]]:
    """Multiply polynomial vector by scalar."""
    return [scalar_mul_poly(scalar, poly, q) for poly in vec]

# Matrix-vector operations in NTT domain
def matrix_vector_mul_ntt(A_hat, s_hat):
    """Multiply matrix by vector in NTT domain.
    
    Args:
        A_hat: k×k matrix in NTT domain (list of lists of polynomials)
        s_hat: k-dimensional vector in NTT domain (list of polynomials)
        
    Returns:
        k-dimensional result vector in NTT domain
    """
    k = len(s_hat)
    result = []
    
    for i in range(k):
        # Compute i-th component: sum of A_hat[i][j] * s_hat[j]
        component = [0] * N
        for j in range(k):
            # A_hat[i][j] is a polynomial, s_hat[j] is a polynomial
            product = multiply_ntts(A_hat[i][j], s_hat[j])
            component = add_poly(component, product, Q)
        result.append(component)
    
    return result

def vector_transpose_mul_ntt(s_hat: List[List[int]], u_hat: List[List[int]]) -> List[int]:
    """Compute s^T * u where both s and u are in NTT domain.
    
    Args:
        s_hat: Vector in NTT domain
        u_hat: Vector in NTT domain
        
    Returns:
        Scalar polynomial result in NTT domain
    """
    k = len(s_hat)
    result = [0] * N
    
    for j in range(k):
        # Multiply in NTT domain
        product = multiply_ntts(s_hat[j], u_hat[j])
        # Add in NTT domain
        for i in range(N):
            result[i] = (result[i] + product[i]) % Q
    
    return result

# Missing function aliases and implementations needed by other modules
def sample_uniform_poly(rho: bytes, i: int, j: int) -> List[int]:
    """Sample uniform polynomial using XOF (wrapper for sample_ntt).
    
    Args:
        rho: 32-byte seed
        i: Row index
        j: Column index
        
    Returns:
        Uniformly sampled polynomial in NTT domain
    """
    # Create 34-byte input: rho || i || j
    input_bytes = rho + bytes([i, j])
    return sample_ntt(input_bytes)

def matrix_vector_multiply_ntt(A_hat, s_hat):
    """Multiply matrix A by vector s in NTT domain (alias for existing function).
    
    Args:
        A_hat: k×k matrix of polynomials in NTT domain
        s_hat: Vector of k polynomials in NTT domain
        
    Returns:
        Vector of k polynomials in NTT domain
    """
    return matrix_vector_mul_ntt(A_hat, s_hat)

def dot_product_ntt(t_hat: List[List[int]], r1_hat: List[List[int]]) -> List[int]:
    """Compute dot product t^T * r1 in NTT domain.
    
    Args:
        t_hat: Vector of k polynomials in NTT domain
        r1_hat: Vector of k polynomials in NTT domain
        
    Returns:
        Single polynomial result in NTT domain
    """
    k = len(t_hat)
    result = [0] * N
    
    for i in range(k):
        product = multiply_ntts(t_hat[i], r1_hat[i])
        for j in range(N):
            result[j] = (result[j] + product[j]) % Q
    
    return result

# Aliases for consistent naming
intt = ntt_inverse  # Inverse NTT alias