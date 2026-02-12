import hashlib
import hmac
import os

def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.
    Uses HMAC for secure comparison to prevent timing attacks.
    '''
    try:
        # Generate a random salt for this specific comparison.  This is crucial.
        salt = os.urandom(16)  # 16 bytes is a reasonable salt size

        # Hash the certificate with the salt.  Use a strong hash algorithm.
        hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate.encode('utf-8'), salt, 100000) # Use PBKDF2 for key derivation

        # Hash the known hash with the same salt.  This ensures a fair comparison.
        hashed_known_hash = hashlib.pbkdf2_hmac('sha256', known_hash.encode('utf-8'), salt, 100000)

        # Securely compare the hashes using hmac.compare_digest.  This prevents timing attacks.
        return hmac.compare_digest(hashed_certificate, hashed_known_hash)

    except Exception as e:
        # Log the error (important for debugging and security monitoring)
        print(f"Error during certificate comparison: {e}")
        return False  # Return False on error to avoid potential security issues

# Example usage (demonstrates secure password hashing and comparison)
def hash_password(password):
    """Hashes a password using PBKDF2 with a random salt."""
    salt = os.urandom(16)
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt + hashed_password  # Store salt + hash

def verify_password(password, stored_hash):
    """Verifies a password against a stored hash (salt + hash)."""
    salt = stored_hash[:16]
    stored_password_hash = stored_hash[16:]
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return hmac.compare_digest(stored_password_hash, hashed_password)


if __name__ == '__main__':
    # Example usage of certificate_matches
    certificate_data = "This is the certificate data."
    known_certificate_hash = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05fdd10102cb48bb4ca942295a4" # Replace with a real hash

    if certificate_matches(certificate_data, known_certificate_hash):
        print("Certificate matches the known hash.")
    else:
        print("Certificate does NOT match the known hash.")

    # Example usage of password hashing and verification
    password = "my_secret_password"
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password.hex()}")

    if verify_password(password, hashed_password):
        print("Password verification successful.")
    else:
        print("Password verification failed.")

    wrong_password = "wrong_password"
    if verify_password(wrong_password, hashed_password):
        print("Password verification should have failed!")
    else:
        print("Password verification correctly failed for wrong password.")

