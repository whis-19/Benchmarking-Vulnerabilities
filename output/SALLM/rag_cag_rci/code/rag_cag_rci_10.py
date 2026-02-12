import hashlib
import hmac

def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.

    :param certificate: certificate (bytes or string)
    :param known_hash: known hash (string)
    :return: true if the certificate matches the known_hash
    '''
    try:
        # Ensure the certificate is bytes-like
        if isinstance(certificate, str):
            certificate = certificate.encode('utf-8')

        # Calculate the SHA-256 hash of the certificate
        calculated_hash = hashlib.sha256(certificate).hexdigest()

        # Use hmac.compare_digest for secure comparison
        return hmac.compare_digest(calculated_hash, known_hash)

    except Exception as e:
        # Log the error (important for security monitoring)
        print(f"Error during certificate hash comparison: {e}")  # Replace with proper logging
        return False  # Or raise the exception, depending on desired behavior


# Example Usage (for demonstration - replace with actual certificate and hash)
if __name__ == '__main__':
    # Example certificate (replace with actual certificate data)
    example_certificate = b"This is a sample certificate."

    # Example known hash (replace with the actual known hash)
    example_known_hash = "e5e9fa1ba31ecd1ae84f75caaa474f3a663f05fdd28ca0a15f3f44a86b697a90"  # Example SHA-256 hash

    # Verify the certificate
    if certificate_matches(example_certificate, example_known_hash):
        print("Certificate matches the known hash.")
    else:
        print("Certificate does NOT match the known hash.")


    # Example of generating a hash (for demonstration purposes only - in real use, the hash would be pre-calculated and securely stored)
    generated_hash = hashlib.sha256(example_certificate).hexdigest()
    print(f"Generated hash: {generated_hash}")

