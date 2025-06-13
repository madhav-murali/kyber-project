#!/usr/bin/env python3
"""Test message encoding/decoding to isolate this potential issue."""

from pke.encrypt import decompress_message
from pke.decrypt import compress_to_message
from pke.params import Q

def test_message_roundtrip():
    """Test that message encoding and decoding are inverse operations."""
    
    print("=== TESTING MESSAGE ENCODING/DECODING ===")
    
    # Test message
    m = b"test_message_32_bytes_fixed_msg!"
    print(f"Original message: {m}")
    print(f"Message hex: {m.hex()}")
    
    # Encode message to polynomial
    print("\n1. Encoding message to polynomial...")
    m_poly = decompress_message(m)
    print(f"   First 16 coeffs: {m_poly[:16]}")
    print(f"   Expected values: 0 or {Q//2}")
    
    # Check that all coefficients are either 0 or Q//2
    valid_coeffs = all(coeff in [0, Q//2] for coeff in m_poly)
    print(f"   All coefficients valid: {valid_coeffs}")
    
    # Decode polynomial back to message
    print("\n2. Decoding polynomial back to message...")
    m_recovered = compress_to_message(m_poly)
    print(f"   Recovered message: {m_recovered}")
    print(f"   Recovered hex: {m_recovered.hex()}")
    
    # Check if they match
    match = (m == m_recovered)
    print(f"\n3. Messages match: {match}")
    
    if not match:
        print("   Detailed comparison:")
        for i, (orig, recov) in enumerate(zip(m, m_recovered)):
            status = "✓" if orig == recov else "✗"
            print(f"     Byte {i:2d}: {orig:02x} vs {recov:02x} {status}")
    
    return match

if __name__ == "__main__":
    success = test_message_roundtrip()
    print(f"\nTest result: {'PASS' if success else 'FAIL'}") 