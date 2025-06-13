#!/usr/bin/env python3
"""Debug ML-KEM with detailed logging to find logical errors."""

import sys
from pke.params import ML_KEM_768
from pke.keygen import k_pke_keygen
from pke.encrypt import k_pke_encrypt
from pke.decrypt import k_pke_decrypt
from kem.keygen import ml_kem_keygen, parse_decapsulation_key
from kem.encaps import ml_kem_encaps_deterministic
from kem.decaps import ml_kem_decaps
from utils.hash_utils import G, H, J
from utils.random_utils import random_bytes

def log_poly(name, poly, max_coeffs=8):
    """Log first few coefficients of a polynomial."""
    if len(poly) > max_coeffs:
        coeffs_str = ", ".join(f"{poly[i]}" for i in range(max_coeffs))
        print(f"  {name}: [{coeffs_str}, ...] (length {len(poly)})")
    else:
        coeffs_str = ", ".join(f"{c}" for c in poly)
        print(f"  {name}: [{coeffs_str}]")

def log_bytes(name, data, max_bytes=16):
    """Log first few bytes of data."""
    if len(data) > max_bytes:
        hex_str = data[:max_bytes].hex()
        print(f"  {name}: {hex_str}... (length {len(data)} bytes)")
    else:
        print(f"  {name}: {data.hex()} (length {len(data)} bytes)")

def debug_test_deterministic():
    """Test ML-KEM with deterministic values and detailed logging."""
    
    print("=== DEBUGGING ML-KEM WITH DETAILED LOGGING ===")
    params = ML_KEM_768
    
    # Use fixed seed for reproducibility
    print("\n1. FIXED INPUTS:")
    d = b"test_seed_32_bytes_deterministic" 
    print(f"  d (key gen seed): {d}")
    
    m = b"test_message_32_bytes_fixed_msg!"
    print(f"  m (message): {m} (length: {len(m)} bytes)")
    
    # Step 1: Key Generation with logging
    print("\n2. KEY GENERATION (K-PKE.KeyGen):")
    try:
        expanded = G(d)
        rho = expanded[:32]
        sigma = expanded[32:64]
        log_bytes("rho", rho)
        log_bytes("sigma", sigma)
        
        ek_pke, dk_pke = k_pke_keygen(d, params)
        print(f"  ✓ K-PKE keys generated successfully")
        log_bytes("ek_pke", ek_pke, 32)
        log_bytes("dk_pke", dk_pke, 32)
        
        # ML-KEM key generation
        z = random_bytes(32)
        ek_pke_hash = H(ek_pke)
        log_bytes("z", z)
        log_bytes("H(ek_pke)", ek_pke_hash)
        
        # Construct ML-KEM keys
        ek = ek_pke
        dk = dk_pke + ek_pke + ek_pke_hash + z
        
        print(f"  ✓ ML-KEM keys constructed")
        print(f"  ek length: {len(ek)} bytes")
        print(f"  dk length: {len(dk)} bytes")
        
    except Exception as e:
        print(f"  ✗ Key generation failed: {e}")
        return False
    
    # Step 2: Encapsulation with logging
    print("\n3. ENCAPSULATION (ML-KEM.Encaps):")
    try:
        # Compute G(m || H(ek))
        ek_hash = H(ek)
        log_bytes("H(ek)", ek_hash)
        
        g_input = m + ek_hash
        g_output = G(g_input)
        K_encaps = g_output[:32]
        r = g_output[32:64]
        
        log_bytes("G input (m||H(ek))", g_input, 32)
        log_bytes("K (from G)", K_encaps)
        log_bytes("r (from G)", r)
        
        # K-PKE Encryption: c = K-PKE.Encrypt(ek, m, r)
        print("  Calling K-PKE.Encrypt...")
        c = k_pke_encrypt(ek, m, r, params)
        log_bytes("ciphertext c", c, 32)
        
        print(f"  ✓ Encapsulation completed")
        shared_secret_encaps = K_encaps
        
    except Exception as e:
        print(f"  ✗ Encapsulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 3: Decapsulation with logging
    print("\n4. DECAPSULATION (ML-KEM.Decaps):")
    try:
        # Parse decapsulation key
        dk_pke_parsed, ek_pke_parsed, h_ek_pke, z_parsed = parse_decapsulation_key(dk, params)
        
        log_bytes("dk_pke (parsed)", dk_pke_parsed, 32)
        log_bytes("ek_pke (parsed)", ek_pke_parsed, 32)
        log_bytes("H(ek_pke) stored", h_ek_pke)
        log_bytes("z (parsed)", z_parsed)
        
        # K-PKE Decryption: m' = K-PKE.Decrypt(dk_pke, c)
        print("  Calling K-PKE.Decrypt...")
        m_prime = k_pke_decrypt(dk_pke_parsed, c, params)
        log_bytes("m' (decrypted)", m_prime)
        
        # Check if m' == m
        print(f"  Message match: {m == m_prime}")
        if m != m_prime:
            print("  ⚠️  Decrypted message doesn't match original!")
            for i, (a, b) in enumerate(zip(m, m_prime)):
                if a != b:
                    print(f"    Byte {i}: {a:02x} != {b:02x}")
        
        # Compute G(m' || H(ek_pke))
        g_input_decaps = m_prime + h_ek_pke
        g_output_decaps = G(g_input_decaps)
        K_prime = g_output_decaps[:32]
        r_prime = g_output_decaps[32:64]
        
        log_bytes("G input (m'||H(ek))", g_input_decaps, 32)
        log_bytes("K' (from G)", K_prime)
        log_bytes("r' (from G)", r_prime)
        
        print(f"  r == r': {r == r_prime}")
        if r != r_prime:
            print("  ⚠️  Re-computed randomness doesn't match!")
        
        # Re-encrypt to verify: c' = K-PKE.Encrypt(ek_pke, m', r')
        print("  Re-encrypting for verification...")
        c_prime = k_pke_encrypt(ek_pke_parsed, m_prime, r_prime, params)
        log_bytes("c' (re-encrypted)", c_prime, 32)
        
        # Check if c == c'
        ciphertext_match = (c == c_prime)
        print(f"  Ciphertext match (c == c'): {ciphertext_match}")
        
        if not ciphertext_match:
            print("  ⚠️  Re-encrypted ciphertext doesn't match!")
            print("  This indicates implicit rejection will be triggered")
            # Count differing bytes
            diff_count = sum(1 for a, b in zip(c, c_prime) if a != b)
            print(f"  Different bytes: {diff_count}/{len(c)}")
        
        if ciphertext_match:
            shared_secret_decaps = K_prime
            print(f"  ✓ Valid ciphertext, using K'")
        else:
            # Implicit rejection
            rejection_input = z_parsed + c
            shared_secret_decaps = J(rejection_input)
            print(f"  ⚠️  Invalid ciphertext, using J(z||c)")
            
        log_bytes("Final shared secret", shared_secret_decaps)
        
    except Exception as e:
        print(f"  ✗ Decapsulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Step 4: Final Verification
    print("\n5. FINAL VERIFICATION:")
    log_bytes("Encaps secret", shared_secret_encaps)
    log_bytes("Decaps secret", shared_secret_decaps)
    
    match = shared_secret_encaps == shared_secret_decaps
    print(f"  Secrets match: {match}")
    
    if not match:
        print("  ⚠️  SECRETS DO NOT MATCH!")
        print("  Detailed comparison:")
        for i, (a, b) in enumerate(zip(shared_secret_encaps, shared_secret_decaps)):
            if a != b:
                print(f"    Byte {i}: {a:02x} != {b:02x}")
    else:
        print("  ✓ SUCCESS! Secrets match perfectly!")
    
    return match

if __name__ == "__main__":
    success = debug_test_deterministic()
    sys.exit(0 if success else 1) 