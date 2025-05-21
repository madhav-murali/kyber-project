import numpy as np

def sample_poly(n=256, q=3329):
    return np.random.randint(low=0, high=q, size=n).tolist()

def add_poly(a, b, q=3329):
    return [(x + y) % q for x, y in zip(a, b)]

def sub_poly(a, b, q=3329):
    return [(x - y) % q for x, y in zip(a, b)]

def mul_poly(a, b, q=3329):
    # Naive convolution
    res = np.convolve(a, b)[:len(a)]
    return [int(x % q) for x in res]