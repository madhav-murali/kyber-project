#!/usr/bin/env python3
"""
Simple ML-KEM Usage Example

A minimal example showing how to use ML-KEM for key encapsulation.
"""

from kyber import ML_KEM_768

def main():
    print("Simple ML-KEM-768 Example")
    print("=" * 30)
    
    # Step 1: Generate a key pair
    print("1. Generating key pair...")
    encapsulation_key, decapsulation_key = ML_KEM_768.keygen()
    print(f"   Public key:  {len(encapsulation_key)} bytes")
    print(f"   Private key: {len(decapsulation_key)} bytes")
    
    # Step 2: Encapsulate (sender side)
    print("\n2. Encapsulating shared secret...")
    shared_secret, ciphertext = ML_KEM_768.encaps(encapsulation_key)
    print(f"   Shared secret: {shared_secret.hex()}")
    print(f"   Ciphertext:    {len(ciphertext)} bytes")
    
    # Step 3: Decapsulate (receiver side)
    print("\n3. Decapsulating shared secret...")
    recovered_secret = ML_KEM_768.decaps(decapsulation_key, ciphertext)
    print(f"   Recovered:     {recovered_secret.hex()}")
    
    # Step 4: Verify
    print("\n4. Verification:")
    if shared_secret == recovered_secret:
        print("   ✓ SUCCESS: Secrets match!")
    else:
        print("   ✗ FAILED: Secrets don't match!")

if __name__ == "__main__":
    main() 