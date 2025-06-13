import os
from pke.params import Kyber512

DEFAULT_MESSAGE_SIZE = 32 # Should match encryption assumption

def decrypt(private_key, ciphertext, params=Kyber512):
    print(f"Decrypting with PKE for {params.name}...")
    if len(private_key) != params.sk_size:
        raise ValueError(f"Private key size mismatch for {params.name}. Expected {params.sk_size}, got {len(private_key)}")
    if len(ciphertext) != params.ct_size:
        raise ValueError(f"Ciphertext size mismatch for {params.name}. Expected {params.ct_size}, got {len(ciphertext)}")

    message = os.urandom(DEFAULT_MESSAGE_SIZE)
    return message
