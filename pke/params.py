class PKEParams:
    def __init__(self, name, k, eta1, eta2, du, dv, n, q, pk_size, sk_size, ct_size):
        self.name = name
        self.k = k # Kyber K parameter (dimension of module)
        self.eta1 = eta1 # Noise parameter for key generation
        self.eta2 = eta2 # Noise parameter for encryption
        self.du = du # Polyvec compression factor for u
        self.dv = dv # Poly compression factor for v
        self.n = n # Degree of polynomials (usually 256)
        self.q = q # Modulus (usually 3329)
        self.pk_size = pk_size # Public key size in bytes (placeholder)
        self.sk_size = sk_size # Secret key size in bytes (placeholder)
        self.ct_size = ct_size # Ciphertext size in bytes (placeholder)

# Placeholder parameters, actual Kyber values need to be accurate
Kyber512 = PKEParams(name="Kyber512", k=2, eta1=3, eta2=2, du=10, dv=4, n=256, q=3329, pk_size=800, sk_size=1632, ct_size=768)
Kyber768 = PKEParams(name="Kyber768", k=3, eta1=2, eta2=2, du=10, dv=4, n=256, q=3329, pk_size=1184, sk_size=2400, ct_size=1088)
Kyber1024 = PKEParams(name="Kyber1024", k=4, eta1=2, eta2=2, du=11, dv=5, n=256, q=3329, pk_size=1568, sk_size=3168, ct_size=1568)
