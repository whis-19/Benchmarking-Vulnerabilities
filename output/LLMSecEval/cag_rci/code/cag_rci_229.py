import os
import hmac
import hashlib

# HMAC key (keep this secret!)
HMAC_KEY = os.environ.get("HMAC_KEY")
if not HMAC_KEY:
    print("Error: HMAC_KEY environment variable not set!")
    exit(1)
HMAC_KEY = HMAC_KEY.encode('utf-8') # Ensure it's bytes

def sign_data(data: bytes) -> bytes:
    """Signs data using HMAC."""
    hmac_obj = hmac.new(HMAC_KEY, data, hashlib.sha256)
    return hmac_obj.digest()

def verify_signature(data: bytes, signature: bytes) -> bool:
    """Verifies the HMAC signature of data."""
    expected_signature = sign_data(data)
    return hmac.compare_digest(expected_signature, signature)

def generate_hmac_key(length=32):
    """Generates a cryptographically secure random HMAC key."""
    return os.urandom(length)

# Example usage:
data = b"This is the data to be signed."
signature = sign_data(data)

# Later, to verify:
is_valid = verify_signature(data, signature)
if is_valid:
    print("Signature is valid.")
    # Process the data
else:
    print("Signature is invalid!")
    # Reject the data

# Example of generating a new key (DO NOT PRINT TO LOGS IN PRODUCTION):
# new_key = generate_hmac_key()
# print(f"Generated HMAC key: {new_key.hex()}") # Print in hex for easy storage/transfer - REMOVE IN PRODUCTION

