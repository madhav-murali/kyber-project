#!/usr/bin/env python3
"""Debug K-PKE encrypt/decrypt operations with detailed logging."""

import sys
from pke.params import ML_KEM_768
from pke.keygen import k_pke_keygen
from pke.encrypt import k_pke_encrypt
from pke.decrypt import k_pke_decrypt
from utils.hash_utils import G, H
from utils.serialization import byte_decode, byte_encode, compress, decompress
from utils.poly_utils import add_poly, sub_poly, ntt, ntt_inverse

def log_bytes(name, data, max_bytes=16):
    """Log first few bytes of data."""
    if len(data) > max_bytes:
        hex_str = data[:max_bytes].hex()
        print(f"  {name}: {hex_str}... (length {len(data)} bytes)")
    else:
        print(f"  {name}: {data.hex()} (length {len(data)} bytes)")

def log_poly(name, poly, max_coeffs=8):
    """Log first few coefficients of a polynomial."""
    if len(poly) > max_coeffs:
        coeffs_str = ", ".join(f"{poly[i]}" for i in range(max_coeffs))
        print(f"  {name}: [{coeffs_str}, ...] (length {len(poly)})")
    else:
        coeffs_str = ", ".join(f"{c}" for c in poly)
        print(f"  {name}: [{coeffs_str}]")

def debug_k_pke():
    """Debug K-PKE encrypt/decrypt with detailed logging."""
    
    print("=== DEBUGGING K-PKE ENCRYPT/DECRYPT ===")
    params = ML_KEM_768
    
    # Use fixed seed for reproducibility
    print("\n1. SETUP:")
    d = b"test_seed_32_bytes_deterministic" 
    m = b"test_message_32_bytes_fixed_msg!"
    
    print(f"  d: {d}")
    print(f"  m: {m}")
    log_bytes("m", m)
    
    # Generate keys
    print("\n2. KEY GENERATION:")
    ek, dk = k_pke_keygen(d, params)
    log_bytes("ek", ek, 32)
    log_bytes("dk", dk, 32)
    
    # Get randomness for encryption
    print("\n3. ENCRYPTION RANDOMNESS:")
    expanded = G(m + H(ek))
    K = expanded[:32]
    r = expanded[32:64]
    log_bytes("r (encryption randomness)", r)
    
    # Manual K-PKE encryption with logging
    print("\n4. MANUAL K-PKE ENCRYPTION:")
    try:
        # Step 1: Decode public key
        print("  4.1 Decoding public key...")
        k = params.k
        du = params.du
        dv = params.dv
        
        # Parse ek = (t, rho)  
        ek_bytes_per_poly = 384  # According to the parameter structure
        t_bytes = ek[:k * ek_bytes_per_poly]
        rho = ek[k * ek_bytes_per_poly:]
        
        print(f"    k={k}, du={du}, dv={dv}")
        print(f"    Expected t_bytes length: {k * ek_bytes_per_poly}")
        print(f"    Actual t_bytes length: {len(t_bytes)}")
        log_bytes("rho from ek", rho)
        
        # Decode t vector
        t_vector = []
        for i in range(k):
            start = i * ek_bytes_per_poly
            end = (i + 1) * ek_bytes_per_poly
            t_i = byte_decode(t_bytes[start:end], 12)
            t_vector.append(t_i)
            log_poly(f"t[{i}]", t_i)
        
        # Step 2: Decode dk for comparison
        print("  4.2 Decoding secret key...")
        dk_bytes_per_poly = 384  # According to the parameter structure
        s_vector = []
        for i in range(k):
            start = i * dk_bytes_per_poly  
            end = (i + 1) * dk_bytes_per_poly
            s_i = byte_decode(dk[start:end], 12)
            s_vector.append(s_i)
            log_poly(f"s[{i}]", s_i)
        
        print("  SUCCESS: Key parsing completed")
        
    except Exception as e:
        print(f"  ERROR in manual encryption: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test K-PKE encrypt
    print("\n5. K-PKE ENCRYPT:")
    try:
        c = k_pke_encrypt(ek, m, r, params)
        log_bytes("ciphertext c", c, 32)
        print(f"  ✓ Encryption successful, ciphertext length: {len(c)}")
    except Exception as e:
        print(f"  ✗ Encryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test K-PKE decrypt
    print("\n6. K-PKE DECRYPT:")
    try:
        m_decrypted = k_pke_decrypt(dk, c, params)
        log_bytes("m' (decrypted)", m_decrypted)
        
        print(f"  Original message : {m}")
        print(f"  Decrypted message: {m_decrypted}")
        
        match = (m == m_decrypted)
        print(f"  Messages match: {match}")
        
        if not match:
            print("  ⚠️  DECRYPTION FAILED!")
            print("  Byte-by-byte comparison:")
            for i, (orig, decr) in enumerate(zip(m, m_decrypted)):
                status = "✓" if orig == decr else "✗"
                print(f"    Byte {i:2d}: {orig:02x} vs {decr:02x} {status}")
        else:
            print("  ✓ SUCCESS: Messages match!")
            
        return match
        
    except Exception as e:
        print(f"  ✗ Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = debug_k_pke()
    sys.exit(0 if success else 1) 