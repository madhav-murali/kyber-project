#!/usr/bin/env python3
"""Simple test to isolate K-PKE encrypt/decrypt issue."""

from pke.params import ML_KEM_768
from pke.keygen import k_pke_keygen
from pke.encrypt import k_pke_encrypt
from pke.decrypt import k_pke_decrypt

def test_k_pke_roundtrip():
    """Test K-PKE encrypt/decrypt roundtrip with known inputs."""
    
    print("=== TESTING K-PKE ROUNDTRIP ===")
    
    # Fixed inputs
    d = b"test_seed_32_bytes_deterministic" 
    m = b"test_message_32_bytes_fixed_msg!"
    r = b"encryption_randomness_32_bytes!!"
    
    params = ML_KEM_768
    
    print(f"Input message: {m}")
    print(f"Message length: {len(m)} bytes")
    print(f"Randomness length: {len(r)} bytes")
    
    # Generate keys
    print("\n1. Generating K-PKE keys...")
    ek, dk = k_pke_keygen(d, params)
    print(f"   Public key length: {len(ek)} bytes")
    print(f"   Secret key length: {len(dk)} bytes")
    
    # Encrypt
    print("\n2. Encrypting...")
    try:
        c = k_pke_encrypt(ek, m, r, params)
        print(f"   Ciphertext length: {len(c)} bytes")
        print(f"   Expected ciphertext length: {params.ct_bytes} bytes")
        print(f"   Encryption successful: {len(c) == params.ct_bytes}")
    except Exception as e:
        print(f"   Encryption failed: {e}")
        return False
    
    # Decrypt  
    print("\n3. Decrypting...")
    try:
        m_recovered = k_pke_decrypt(dk, c, params)
        print(f"   Decrypted length: {len(m_recovered)} bytes")
        print(f"   Original : {m}")
        print(f"   Recovered: {m_recovered}")
        
        # Check if they match
        match = (m == m_recovered)
        print(f"   Match: {match}")
        
        if not match:
            print("   Detailed comparison:")
            for i, (orig, decr) in enumerate(zip(m, m_recovered)):
                status = "✓" if orig == decr else "✗" 
                print(f"     Byte {i:2d}: {orig:02x} vs {decr:02x} {status}")
        
        return match
        
    except Exception as e:
        print(f"   Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_k_pke_roundtrip()
    print(f"\nTest result: {'PASS' if success else 'FAIL'}") 