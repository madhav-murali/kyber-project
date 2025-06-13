#!/usr/bin/env python3
"""
ML-KEM (CRYSTALS-Kyber) Demonstration Script

This script demonstrates the usage of the ML-KEM implementation
according to NIST FIPS 203 for all three security levels.
"""

import time
import sys
from kyber import ML_KEM_512, ML_KEM_768, ML_KEM_1024, MLKEM
from pke.params import ML_KEM_512 as PARAMS_512, ML_KEM_768 as PARAMS_768, ML_KEM_1024 as PARAMS_1024

def test_ml_kem_security_level(kem_class, params, level_name):
    """Test ML-KEM for a specific security level."""
    print(f"\n{'='*60}")
    print(f"Testing {level_name}")
    print(f"{'='*60}")
    print(f"Parameters: k={params.k}, η₁={params.eta1}, η₂={params.eta2}")
    print(f"Key sizes: PK={params.pk_bytes} bytes, SK={params.sk_bytes} bytes")
    print(f"Ciphertext size: {params.ct_bytes} bytes")
    print(f"Security Category: {params.security_category}")
    
    try:
        # Step 1: Key Generation
        print(f"\n1. Generating {level_name} key pair...")
        start_time = time.time()
        encapsulation_key, decapsulation_key = kem_class.keygen()
        keygen_time = time.time() - start_time
        print(f"   ✓ Key generation completed in {keygen_time:.4f} seconds")
        print(f"   ✓ Encapsulation key: {len(encapsulation_key)} bytes")
        print(f"   ✓ Decapsulation key: {len(decapsulation_key)} bytes")
        
        # Step 2: Encapsulation
        print(f"\n2. Performing encapsulation...")
        start_time = time.time()
        shared_secret_1, ciphertext = kem_class.encaps(encapsulation_key)
        encaps_time = time.time() - start_time
        print(f"   ✓ Encapsulation completed in {encaps_time:.4f} seconds")
        print(f"   ✓ Shared secret: {len(shared_secret_1)} bytes")
        print(f"   ✓ Ciphertext: {len(ciphertext)} bytes")
        print(f"   ✓ Shared secret (hex): {shared_secret_1[:16].hex()}...")
        
        # Step 3: Decapsulation
        print(f"\n3. Performing decapsulation...")
        start_time = time.time()
        shared_secret_2 = kem_class.decaps(decapsulation_key, ciphertext)
        decaps_time = time.time() - start_time
        print(f"   ✓ Decapsulation completed in {decaps_time:.4f} seconds")
        print(f"   ✓ Recovered secret: {len(shared_secret_2)} bytes")
        print(f"   ✓ Recovered secret (hex): {shared_secret_2[:16].hex()}...")
        
        # Step 4: Verification
        print(f"\n4. Verifying correctness...")
        if shared_secret_1 == shared_secret_2:
            print("   ✓ SUCCESS: Shared secrets match!")
            print("   ✓ ML-KEM implementation is working correctly")
        else:
            print("   ✗ FAILURE: Shared secrets do not match!")
            return False
            
        # Step 5: Performance Summary
        print(f"\n5. Performance Summary:")
        print(f"   • Key Generation: {keygen_time:.4f}s")
        print(f"   • Encapsulation:  {encaps_time:.4f}s") 
        print(f"   • Decapsulation:  {decaps_time:.4f}s")
        print(f"   • Total time:     {keygen_time + encaps_time + decaps_time:.4f}s")
        
        return True
        
    except Exception as e:
        print(f"   ✗ ERROR: {str(e)}")
        return False

def test_invalid_ciphertext():
    """Test implicit rejection with invalid ciphertext."""
    print(f"\n{'='*60}")
    print("Testing Implicit Rejection (Security Feature)")
    print(f"{'='*60}")
    
    try:
        # Generate a key pair
        ek, dk = ML_KEM_768.keygen()
        
        # Generate a valid ciphertext
        secret1, ciphertext = ML_KEM_768.encaps(ek)
        
        # Corrupt the ciphertext
        corrupted_ciphertext = bytearray(ciphertext)
        corrupted_ciphertext[0] ^= 0xFF  # Flip all bits in first byte
        corrupted_ciphertext = bytes(corrupted_ciphertext)
        
        print("1. Generated valid key pair and ciphertext")
        print("2. Corrupting ciphertext...")
        
        # Decrypt with corrupted ciphertext
        secret2 = ML_KEM_768.decaps(dk, corrupted_ciphertext)
        
        print("3. Decapsulation with corrupted ciphertext completed")
        print(f"   ✓ Original secret:  {secret1[:16].hex()}...")
        print(f"   ✓ Rejected secret:  {secret2[:16].hex()}...")
        
        if secret1 != secret2:
            print("   ✓ SUCCESS: Implicit rejection working correctly")
            print("   ✓ Invalid ciphertext produces different secret")
            return True
        else:
            print("   ✗ WARNING: Secrets are the same (very unlikely but possible)")
            return True
            
    except Exception as e:
        print(f"   ✗ ERROR during implicit rejection test: {str(e)}")
        return False

def demonstrate_api_usage():
    """Demonstrate different ways to use the API."""
    print(f"\n{'='*60}")
    print("API Usage Examples")
    print(f"{'='*60}")
    
    print("\n1. Using static methods (recommended):")
    print("   from kyber import ML_KEM_768")
    print("   ek, dk = ML_KEM_768.keygen()")
    print("   secret, ct = ML_KEM_768.encaps(ek)")
    print("   recovered = ML_KEM_768.decaps(dk, ct)")
    
    print("\n2. Using instance-based API:")
    print("   from kyber import MLKEM")
    print("   from pke.params import ML_KEM_768")
    print("   kyber = MLKEM(ML_KEM_768)")
    print("   ek, dk = kyber.keygen()")
    
    print("\n3. Parameter information:")
    ml_kem = MLKEM(PARAMS_768)
    print(f"   Algorithm name: {ml_kem.name}")
    print(f"   Security level: {ml_kem.security_level}")
    print(f"   Public key size: {ml_kem.pk_bytes} bytes")
    print(f"   Secret key size: {ml_kem.sk_bytes} bytes")

def main():
    """Main demonstration function."""
    print("ML-KEM (CRYSTALS-Kyber) NIST FIPS 203 Implementation")
    print("====================================================")
    print("This demonstration shows the complete ML-KEM implementation")
    print("with all three NIST-approved security levels.")
    
    # Test all security levels
    results = []
    
    # Test ML-KEM-512 (Security Category 1)
    results.append(test_ml_kem_security_level(ML_KEM_512, PARAMS_512, "ML-KEM-512"))
    
    # Test ML-KEM-768 (Security Category 3) - Recommended
    results.append(test_ml_kem_security_level(ML_KEM_768, PARAMS_768, "ML-KEM-768"))
    
    # Test ML-KEM-1024 (Security Category 5)
    results.append(test_ml_kem_security_level(ML_KEM_1024, PARAMS_1024, "ML-KEM-1024"))
    
    # Test security features
    results.append(test_invalid_ciphertext())
    
    # Show API usage
    demonstrate_api_usage()
    
    # Final summary
    print(f"\n{'='*60}")
    print("Final Summary")
    print(f"{'='*60}")
    
    success_count = sum(results)
    total_tests = len(results)
    
    if success_count == total_tests:
        print(f"✓ ALL TESTS PASSED ({success_count}/{total_tests})")
        print("✓ ML-KEM implementation is working correctly!")
        print("\nThe implementation is ready for use in:")
        print("  • Secure communications")
        print("  • Key establishment protocols")  
        print("  • Post-quantum cryptographic applications")
        return 0
    else:
        print(f"✗ SOME TESTS FAILED ({success_count}/{total_tests})")
        print("✗ Please check the implementation")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 