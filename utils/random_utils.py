import os

def random_bytes(n: int) -> bytes:
    return os.urandom(n)