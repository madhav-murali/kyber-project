#!/usr/bin/env python3
"""Debug test to find where ML-KEM is failing."""

from kyber import ML_KEM_768

def debug_test():
    try:
        print("1. Testing key generation...")
        ek, dk = ML_KEM_768.keygen()
        print('✓ Key generation successful')
        print(f'   Public key: {len(ek)} bytes')
        print(f'   Private key: {len(dk)} bytes')
        
        print("\n2. Testing encapsulation...")
        secret1, ct = ML_KEM_768.encaps(ek)
        print('✓ Encapsulation successful')
        print(f'   Secret: {secret1[:8].hex()}...')
        print(f'   Ciphertext: {len(ct)} bytes')
        
        print("\n3. Testing decapsulation...")
        secret2 = ML_KEM_768.decaps(dk, ct)
        print('✓ Decapsulation successful')
        print(f'   Recovered: {secret2[:8].hex()}...')
        
        print(f"\n4. Verification:")
        print(f'   Original:  {secret1.hex()}')
        print(f'   Recovered: {secret2.hex()}')
        print(f'   Match: {secret1 == secret2}')
        
        if secret1 != secret2:
            print("\n5. Detailed comparison:")
            for i, (a, b) in enumerate(zip(secret1, secret2)):
                if a != b:
                    print(f'   Byte {i}: {a:02x} != {b:02x}')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    debug_test() 