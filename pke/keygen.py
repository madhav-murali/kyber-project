import os
from pke.params import Kyber512 # Default params

def keygen(params=Kyber512):
    print(f"Generating PKE keys for {params.name}...")
    public_key = os.urandom(params.pk_size)
    private_key = os.urandom(params.sk_size)
    return public_key, private_key
