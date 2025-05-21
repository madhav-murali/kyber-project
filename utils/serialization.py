def poly_to_bytes(poly, q=3329, n=256):
    return b''.join([(x % q).to_bytes(2, 'little') for x in poly])

def bytes_to_poly(data, q=3329):
    return [int.from_bytes(data[i:i+2], 'little') % q for i in range(0, len(data), 2)]

def vec_to_bytes(vec):
    return b''.join([poly_to_bytes(p) for p in vec])

def bytes_to_vec(data, k=2, n=256):
    poly_len = n * 2
    return [bytes_to_poly(data[i:i+poly_len]) for i in range(0, k * poly_len, poly_len)]