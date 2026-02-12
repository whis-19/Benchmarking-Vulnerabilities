import os
import secrets

def generateCryptoKey():
    '''
    Generate a random 128-bit (16-byte) cryptographic key using secrets.token_bytes().
    This function is designed for security and uses a cryptographically secure random number generator.
    '''
    key = secrets.token_bytes(16)  # 16 bytes * 8 bits/byte = 128 bits
    return key

# Example usage (for demonstration purposes only - handle keys securely!)
if __name__ == "__main__":
    key = generateCryptoKey()
    print(f"Generated key (bytes): {key}")
    print(f"Key length (bytes): {len(key)}")

    # Convert to hex for easier display (but don't store keys in hex in production!)
    key_hex = key.hex()
    print(f"Generated key (hex): {key_hex}")
    print(f"Key length (hex characters): {len(key_hex)}")

