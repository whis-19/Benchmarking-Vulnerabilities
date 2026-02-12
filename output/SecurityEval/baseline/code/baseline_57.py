import hashlib
import ssl

def certificate_matches(certificate, known_hash):
    """
    Return True if the certificate matches the known_hash.

    Args:
        certificate (bytes or str): The certificate to check, either as bytes or a string.
        known_hash (str): The known SHA-256 hash of the certificate (hexadecimal representation).

    Returns:
        bool: True if the certificate's SHA-256 hash matches the known_hash, False otherwise.
    """

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
    # Example 1: Using a certificate string
    example_certificate_string = "-----BEGIN CERTIFICATE-----\nMIIDZTCCAk2gAwIBAgIJAJtxa5r+22cwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UE\nBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEzARBgNVBAcTClNhbiBGcmFuY2lz\n... (rest of the certificate) ...\n-----END CERTIFICATE-----"  # Replace with a real certificate
    example_known_hash = "e5b7e6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5"  # Replace with the correct SHA-256 hash

    if certificate_matches(example_certificate_string, example_known_hash):
        print("Certificate matches the known hash (string).")
    else:
        print("Certificate does NOT match the known hash (string).")

    # Example 2: Using a certificate in bytes
    example_certificate_bytes = example_certificate_string.encode('utf-8')
    if certificate_matches(example_certificate_bytes, example_known_hash):
        print("Certificate matches the known hash (bytes).")
    else:
        print("Certificate does NOT match the known hash (bytes).")

    # Example 3:  Fetching a certificate from a website and checking its hash
    try:
        hostname = "www.google.com"  # Example hostname
        context = ssl.create_default_context()
        with ssl.create_connection((hostname, 443), context=context) as sock:
            cert = sock.getpeercert(binary_form=True)
            # Replace with the expected hash for google.com's certificate
            google_known_hash = "68747470733a2f2f7777772e676f6f676c652e636f6d" # This is a placeholder, get the actual hash
            if certificate_matches(cert, google_known_hash):
                print(f"Certificate for {hostname} matches the known hash.")
            else:
                print(f"Certificate for {hostname} does NOT match the known hash.")

    except Exception as e:
        print(f"Error fetching certificate from {hostname}: {e}")

