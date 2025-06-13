import sys
import os
import time

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from kem import keygen, encapsulate, decapsulate, Kyber512_KEM # Import params as well if needed by benchmarks

# Number of iterations for benchmarking
ITERATIONS = 100

def benchmark_keygen():
    """Benchmarks the keygen() function."""
    start_time = time.time()
    for _ in range(ITERATIONS):
        keygen(params=Kyber512_KEM)
    end_time = time.time()
    average_time = (end_time - start_time) / ITERATIONS
    print(f"Average time per key generation: {average_time:.6f} seconds")

def benchmark_encapsulate():
    """Benchmarks the encapsulate() function."""
    public_key, _ = keygen(params=Kyber512_KEM)
    start_time = time.time()
    for _ in range(ITERATIONS):
        encapsulate(public_key, params=Kyber512_KEM)
    end_time = time.time()
    average_time = (end_time - start_time) / ITERATIONS
    print(f"Average time per encapsulation: {average_time:.6f} seconds")

def benchmark_decapsulate():
    """Benchmarks the decapsulate() function."""
    public_key, private_key = keygen(params=Kyber512_KEM)
    ciphertexts = []
    for _ in range(ITERATIONS):
        ciphertext, _ = encapsulate(public_key, params=Kyber512_KEM)
        ciphertexts.append(ciphertext)

    start_time = time.time()
    for ciphertext in ciphertexts:
        decapsulate(private_key, ciphertext, params=Kyber512_KEM)
    end_time = time.time()
    average_time = (end_time - start_time) / ITERATIONS
    print(f"Average time per decapsulation: {average_time:.6f} seconds")

if __name__ == "__main__":
    print(f"Running benchmarks with {ITERATIONS} iterations...\n")
    benchmark_keygen()
    benchmark_encapsulate()
    benchmark_decapsulate()
