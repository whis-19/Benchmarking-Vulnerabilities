```python
import hashlib
import hmac
import secrets
import os
import logging
import ssl  # For certificate parsing and validation
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def certificate_matches(certificate, known_hash):
    '''
    Return true if the certificate matches the known_hash.

    :param certificate: certificate (bytes or string)
    :param known_hash: known hash (string)
    :return: true if the certificate matches the known_hash
    '''

    if isinstance(certificate, str):
        certificate = certificate.encode('utf-8')  # Encode to bytes if it's a string

    try:
        # Decode the stored hash from hex to bytes
        salt = bytes.fromhex(known_hash[:32])  # Extract salt (first 16 bytes, hex encoded)
        stored_hashed_certificate = bytes.fromhex(known_hash[32:]) # Extract hash (remaining bytes, hex encoded)

        # Hash the certificate using a strong hashing algorithm with the salt.
        hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate, salt, 100000)  # Use PBKDF2 for key derivation

        # Securely compare the generated hash with the stored hash using hmac.compare_digest.
        # This prevents timing attacks.
        return hmac.compare_digest(hashed_certificate, stored_hashed_certificate)
    except (TypeError, ValueError) as e:
        logging.error(f"Error during certificate comparison: {e}")
        return False


def generate_initial_hash(certificate):
    '''
    Generates the initial hash for a certificate.  This is used when the certificate
    is first added to the system.  It includes salting and PBKDF2.

    :param certificate: The certificate (bytes or string)
    :return: The hex representation of the salted and hashed certificate.  This should be stored.
    '''

    if isinstance(certificate, str):
        certificate = certificate.encode('utf-8')

    salt = secrets.token_bytes(16)
    hashed_certificate = hashlib.pbkdf2_hmac('sha256', certificate, salt, 100000)
    combined_hash = salt + hashed_certificate
    return combined_hash.hex()


def validate_certificate(certificate_data):
    '''
    Validates the certificate data to prevent injection attacks and other vulnerabilities.
    This example focuses on basic parsing and checks for common issues.  More comprehensive
    validation may be required depending on the specific use case.

    :param certificate_data: The certificate data (bytes).
    :raises ValueError: If the certificate is invalid.
    '''
    try:
        # Attempt to load the certificate using cryptography.
        cert = x509.load_pem_x509_certificate(certificate_data, default_backend())

        # Check the certificate's signature algorithm.  Weak algorithms should be rejected.
        if cert.signature_algorithm.name in ['md5WithRSAEncryption', 'sha1WithRSAEncryption']:
            raise ValueError("Certificate uses a weak signature algorithm.")

        # Check the certificate's key size.  Small key sizes are vulnerable to attack.
        key = cert.public_key()
        if hasattr(key, "key_size") and key.key_size < 2048:
            raise ValueError("Certificate uses a weak key size.")

        # Check for basic constraints (is it a CA certificate?).  This might be relevant
        # depending on the intended use of the certificate.
        # Example: if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        #     raise ValueError("Certificate is a CA certificate and should not be used for this purpose.")

        # Add more checks as needed, such as:
        # - Checking the validity period (notBefore and notAfter).
        # - Checking the issuer and subject names.
        # - Checking for specific extensions.

        logging.info("Certificate validation successful.")

    except ValueError as e:
        logging.error(f"Certificate validation failed: {e}")
        raise
    except Exception as e:
        logging.error(f"Error during certificate parsing: {e}")
        raise ValueError("Invalid certificate format.") from e


# Example Usage (and demonstration of secure storage practices)
if __name__ == '__main__':
    # Simulate a certificate
    certificate_data = b"-----BEGIN CERTIFICATE-----\nMIIDZTCCAk2gAwIBAgIJAJrzH/9eu+wwDQYJKoZIhvcNAQELBQAwgbExCzAJBgNV\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLTW91bnRhaW4gVmlldzEQMA4G\nA1UECgwHVGVsZWdyYW0xEjAQBgNVBAsMCU1lc3NhZ2luZzEWMBQGA1UEAwwNdGVs\nZWdyYW0ub3JnMSEwHwYDVQQKExhUZWxlZ3JhbSBGcmFtZXdvcmssIEluYy4xHzAd\nBgkqhkiG9w0BCQEWEHRlbGVncmFtQHRlbGVncmFtMB4XDTIzMTAyNjE0NDQ0NVoX\nDTI0MTAyNTE0NDQ0NVowgbExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIG\nA1UEBwwLTW91bnRhaW4gVmlldzEQMA4GA1UECgwHVGVsZWdyYW0xEjAQBgNVBAsM\nCU1lc3NhZ2luZzEWMBQGA1UEAwwNdGVsZWdyYW0ub3JnMSEwHwYDVQQKExhUZWxl\nZ3JhbSBGcmFtZXdvcmssIEluYy4xHzAdBgkqhkiG9w0BCQEWEHRlbGVncmFtQHRl\nbGVncmFtMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw1+a+3R30+4j\n4k0394698+0989+789+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489+489+489+489+489+489+489+489+489+489+4\n89+489+489+489+489+489+489

