import hashlib
import hmac
import os

def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.
    '''
    try:
        # Generate a random salt for this specific comparison.  This is crucial.
        salt = os.urandom(16)  # 16 bytes is a reasonable salt size

        # Hash the certificate with the salt.  Use a strong hashing algorithm.
        hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate.encode('utf-8'), salt, 100000)  # Adjust iterations as needed

        # Combine the salt and the hash for storage or comparison.  
        # In a real system, you'd likely store the salt alongside the hash.
        # For this example, we'll just prepend it for comparison purposes.
        combined_hash = salt + hashed_certificate

        # Securely compare the generated hash with the known hash using hmac.compare_digest.
        # This prevents timing attacks.  Crucially important.
        return hmac.compare_digest(combined_hash, known_hash)

    except Exception as e:
        # Log the error appropriately.  Don't expose sensitive information in the log.
        print(f"Error during certificate comparison: {e}")  # Replace with proper logging
        return False  # Or raise the exception, depending on desired behavior


# Example usage (for demonstration purposes only - adapt to your specific needs)
if __name__ == '__main__':
    # Simulate a certificate
    certificate_data = "This is the certificate content."

    # Generate a known hash (this would typically be done during certificate registration)
    salt = os.urandom(16)
    known_hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate_data.encode('utf-8'), salt, 100000)
    known_hash = salt + known_hashed_certificate

    # Simulate a comparison
    is_match = certificate_matches(certificate_data, known_hash)

    if is_match:
        print("Certificate matches!")
    else:
        print("Certificate does NOT match!")

    # Example of a mismatch
    different_certificate = "This is a different certificate."
    is_match = certificate_matches(different_certificate, known_hash)

    if is_match:
        print("Certificate matches (incorrectly)!")
    else:
        print("Certificate does NOT match (correctly)!")

