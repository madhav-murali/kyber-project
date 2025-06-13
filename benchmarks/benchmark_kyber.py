import time
import sys
import os

# Add the project root to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pke import keygen as pke_keygen
from pke import encrypt as pke_encrypt
from pke import decrypt as pke_decrypt
from pke import Kyber512, Kyber768, Kyber1024

# Number of iterations for benchmarking
DEFAULT_ITERATIONS = 100
MESSAGE_SIZE = 32 # Consistent with pke.encrypt placeholder

def benchmark_pke_keygen(params, iterations):
    """Benchmarks the PKE keygen() function for a given parameter set."""
    start_time = time.time()
    for _ in range(iterations):
        pke_keygen(params=params)
    end_time = time.time()
    average_time = (end_time - start_time) / iterations
    print(f"  Average PKE keygen time: {average_time:.6f} seconds")

def benchmark_pke_encrypt(params, iterations):
    """Benchmarks the PKE encrypt() function for a given parameter set."""
    public_key, _ = pke_keygen(params=params)
    message = os.urandom(MESSAGE_SIZE)

    start_time = time.time()
    for _ in range(iterations):
        pke_encrypt(public_key, message, params=params)
    end_time = time.time()
    average_time = (end_time - start_time) / iterations
    print(f"  Average PKE encrypt time: {average_time:.6f} seconds")

def benchmark_pke_decrypt(params, iterations):
    """Benchmarks the PKE decrypt() function for a given parameter set."""
    public_key, private_key = pke_keygen(params=params)
    message = os.urandom(MESSAGE_SIZE)

    ciphertexts = []
    for _ in range(iterations):
        ct = pke_encrypt(public_key, message, params=params)
        ciphertexts.append(ct)

    start_time = time.time()
    for ciphertext in ciphertexts:
        pke_decrypt(private_key, ciphertext, params=params)
    end_time = time.time()
    average_time = (end_time - start_time) / iterations
    print(f"  Average PKE decrypt time: {average_time:.6f} seconds")

if __name__ == "__main__":
    all_params = [Kyber512, Kyber768, Kyber1024]
    ITERATIONS = DEFAULT_ITERATIONS # Use the defined default

    print(f"Starting PKE Benchmarks (iterations per operation = {ITERATIONS})\n")

    for params in all_params:
        print(f"Benchmarking for {params.name}...")

        # For keygen, we generate multiple key pairs
        benchmark_pke_keygen(params, ITERATIONS)

        # For encrypt, we generate one key pair, then encrypt multiple times
        benchmark_pke_encrypt(params, ITERATIONS)

        # For decrypt, we generate one key pair, encrypt multiple messages, then decrypt them
        benchmark_pke_decrypt(params, ITERATIONS)

        print("-" * 40)

    print("\nPKE Benchmarks Finished.")
