import hashlib
import ssl

def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.

    :param certificate: certificate (bytes or string)
    :param known_hash: known hash (string, hex encoded)
    :return: true if the certificate matches the known_hash
    '''
    try:
        if isinstance(certificate, str):
            certificate_bytes = certificate.encode('utf-8')  # Encode to bytes if it's a string
        elif isinstance(certificate, bytes):
            certificate_bytes = certificate
        else:
            raise TypeError("Certificate must be a string or bytes.")

        # Calculate the SHA-256 hash of the certificate
        cert_hash = hashlib.sha256(certificate_bytes).hexdigest()

        # Compare the calculated hash with the known hash (case-insensitive)
        return cert_hash.lower() == known_hash.lower()

    except Exception as e:
        print(f"Error during certificate hash comparison: {e}")  # Log the error
        return False  # Return False in case of any error
    

# Example Usage (replace with your actual certificate and hash)
if __name__ == '__main__':
    # Example 1: Using a string certificate
    example_certificate_string = "-----BEGIN CERTIFICATE-----\nMIIDZTCCAk2gAwIBAgIJAJtxub+9+94wDQYJKoZIhvcNAQELBQAwgbExCzAJBgNV\n...\n-----END CERTIFICATE-----"  # Replace with your actual certificate string
    example_known_hash = "e5b7e6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"  # Replace with your actual known hash

    if certificate_matches(example_certificate_string, example_known_hash):
        print("Certificate matches the known hash (string).")
    else:
        print("Certificate does NOT match the known hash (string).")

    # Example 2: Using a bytes certificate
    example_certificate_bytes = b"-----BEGIN CERTIFICATE-----\nMIIDZTCCAk2gAwIBAgIJAJtxub+9+94wDQYJKoZIhvcNAQELBQAwgbExCzAJBgNV\n...\n-----END CERTIFICATE-----"  # Replace with your actual certificate bytes
    example_known_hash = "e5b7e6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"  # Replace with your actual known hash

    if certificate_matches(example_certificate_bytes, example_known_hash):
        print("Certificate matches the known hash (bytes).")
    else:
        print("Certificate does NOT match the known hash (bytes).")

    # Example 3:  Demonstrating error handling with an invalid certificate type
    try:
        certificate_matches(123, example_known_hash)
    except TypeError as e:
        print(f"Caught expected TypeError: {e}")

