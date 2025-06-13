class KEMParams:
    def __init__(self, name, security_level, pk_size, sk_size, ct_size, ss_size):
        self.name = name
        self.security_level = security_level # e.g., 128-bit
        self.pk_size = pk_size # public key size in bytes
        self.sk_size = sk_size # secret key size in bytes
        self.ct_size = ct_size # ciphertext size in bytes
        self.ss_size = ss_size # shared secret size in bytes

# Placeholder parameters, actual Kyber values are different
Kyber512_KEM = KEMParams(
    name="Kyber512_KEM",
    security_level=128,
    pk_size=800, # Placeholder
    sk_size=1632, # Placeholder
    ct_size=768, # Placeholder
    ss_size=32 # Placeholder
)
