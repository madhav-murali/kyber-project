import hashlib

def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def shake128(data: bytes, outlen: int) -> bytes:
    return hashlib.shake_128(data).digest(outlen)