import hashlib

def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash function.
    
    Args:
        data: Input byte array
        
    Returns:
        32-byte hash digest
    """
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    """SHA3-512 hash function.
    
    Args:
        data: Input byte array
        
    Returns:
        64-byte hash digest
    """
    return hashlib.sha3_512(data).digest()

def shake128(data: bytes, outlen: int) -> bytes:
    """SHAKE128 extendable-output function.
    
    Args:
        data: Input byte array
        outlen: Desired output length in bytes
        
    Returns:
        Variable-length output
    """
    return hashlib.shake_128(data).digest(outlen)

def shake256(data: bytes, outlen: int) -> bytes:
    """SHAKE256 extendable-output function.
    
    Args:
        data: Input byte array
        outlen: Desired output length in bytes
        
    Returns:
        Variable-length output
    """
    return hashlib.shake_256(data).digest(outlen)

# FIPS 203 Wrapper Functions

def H(s: bytes) -> bytes:
    """Hash function H as defined in FIPS 203.
    H(s) := SHA3-256(s)
    
    Args:
        s: Variable-length input
        
    Returns:
        32-byte output
    """
    return sha3_256(s)

def J(s: bytes) -> bytes:
    """Hash function J as defined in FIPS 203.
    J(s) := SHAKE256(s, 32)
    
    Args:
        s: Variable-length input
        
    Returns:
        32-byte output
    """
    return shake256(s, 32)

def G(c: bytes) -> bytes:
    """Hash function G as defined in FIPS 203.
    G(c) := SHA3-512(c), returns 64-byte output to be split by caller
    
    Args:
        c: Variable-length input
        
    Returns:
        64-byte output that can be split into two 32-byte parts
    """
    return sha3_512(c)

def PRF(eta: int, s: bytes, b: bytes) -> bytes:
    """Pseudorandom function PRF as defined in FIPS 203.
    PRF_η(s, b) := SHAKE256(s || b, 64·η)
    
    Args:
        eta: Parameter η ∈ {2, 3}
        s: 32-byte input
        b: 1-byte input
        
    Returns:
        (64·η)-byte output
    """
    if eta not in {2, 3}:
        raise ValueError("eta must be 2 or 3")
    if len(s) != 32:
        raise ValueError("s must be 32 bytes")
    if len(b) != 1:
        raise ValueError("b must be 1 byte")
    
    return shake256(s + b, 64 * eta)

class XOF:
    """Extendable-Output Function wrapper for SHAKE128.
    XOF(ρ, i, j) := SHAKE128(ρ || i || j)
    """
    
    def __init__(self, rho: bytes, i: int, j: int):
        """Initialize XOF with seed and indices.
        
        Args:
            rho: 32-byte seed
            i: First index (0-255)
            j: Second index (0-255)
        """
        if len(rho) != 32:
            raise ValueError("rho must be 32 bytes")
        if not (0 <= i <= 255):
            raise ValueError("i must be in range [0, 255]")
        if not (0 <= j <= 255):
            raise ValueError("j must be in range [0, 255]")
            
        self._shake = hashlib.shake_128()
        self._shake.update(rho + bytes([i, j]))
    
    def squeeze(self, length: int) -> bytes:
        """Squeeze bytes from the XOF.
        
        Args:
            length: Number of bytes to output
            
        Returns:
            Variable-length output
        """
        return self._shake.digest(length)