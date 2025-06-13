"""
Parameter sets for ML-KEM as specified in NIST FIPS 203.

This module defines the three approved parameter sets:
- ML-KEM-512 (Security Category 1)
- ML-KEM-768 (Security Category 3) 
- ML-KEM-1024 (Security Category 5)
"""

from dataclasses import dataclass
from typing import Dict

# Global constants (same for all parameter sets)
N = 256  # Polynomial degree
Q = 3329  # Prime modulus q = 2^8 * 13 + 1
ZETA = 17  # Primitive 256th root of unity modulo q

@dataclass(frozen=True)
class MLKEMParams:
    """ML-KEM parameter set.
    
    Attributes:
        name: Parameter set name
        k: Module dimension
        eta1: Noise parameter η₁ for secret/error vectors in key generation
        eta2: Noise parameter η₂ for error vectors in encryption
        du: Number of bits for compressing u vector
        dv: Number of bits for compressing v polynomial
        security_category: NIST security category (1, 3, or 5)
    """
    name: str
    k: int
    eta1: int
    eta2: int
    du: int
    dv: int
    security_category: int
    
    @property
    def pk_bytes(self) -> int:
        """Size of public key (encapsulation key) in bytes."""
        return 384 * self.k + 32
    
    @property
    def sk_bytes(self) -> int:
        """Size of secret key (decapsulation key) in bytes."""
        return 768 * self.k + 96
    
    @property
    def ct_bytes(self) -> int:
        """Size of ciphertext in bytes."""
        return 32 * (self.du * self.k + self.dv)
    
    @property
    def ss_bytes(self) -> int:
        """Size of shared secret in bytes."""
        return 32

# ML-KEM Parameter Sets as defined in FIPS 203 Table 2
ML_KEM_512 = MLKEMParams(
    name="ML-KEM-512",
    k=2,
    eta1=3,
    eta2=2,
    du=10,
    dv=4,
    security_category=1
)

ML_KEM_768 = MLKEMParams(
    name="ML-KEM-768", 
    k=3,
    eta1=2,
    eta2=2,
    du=10,
    dv=4,
    security_category=3
)

ML_KEM_1024 = MLKEMParams(
    name="ML-KEM-1024",
    k=4,
    eta1=2,
    eta2=2,
    du=11,
    dv=5,
    security_category=5
)

# Parameter set lookup
PARAMETER_SETS: Dict[str, MLKEMParams] = {
    "ML-KEM-512": ML_KEM_512,
    "ML-KEM-768": ML_KEM_768,
    "ML-KEM-1024": ML_KEM_1024
}

def get_params(name: str) -> MLKEMParams:
    """Get parameter set by name.
    
    Args:
        name: Parameter set name
        
    Returns:
        Parameter set object
        
    Raises:
        ValueError: If parameter set name is not recognized
    """
    if name not in PARAMETER_SETS:
        valid_names = list(PARAMETER_SETS.keys())
        raise ValueError(f"Unknown parameter set '{name}'. Valid options: {valid_names}")
    
    return PARAMETER_SETS[name]

# Default parameter set
DEFAULT_PARAMS = ML_KEM_768

