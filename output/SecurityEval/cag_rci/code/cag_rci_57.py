import re
import logging
import secrets
from enum import Enum
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature, InvalidVersion, CryptoError

class HashAlgorithm(Enum):
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'

def certificate_matches(certificate_pem, known_hash, hash_algorithm=HashAlgorithm.SHA512.value):
    """
    Return True if the certificate's hash matches the known_hash.

    Args:
        certificate_pem (bytes or str): The certificate in PEM format (bytes or string).
        known_hash (str): The expected hash of the certificate (hexadecimal string).
        hash_algorithm (str): The hashing algorithm to use (e.g., 'sha256').  Defaults to 'sha512'.

    Returns:
        bool: True if the certificate's hash matches the known_hash, False otherwise.
              Returns False if the certificate is invalid or an error occurs during hashing.
              Note: This function does NOT perform certificate chain validation or revocation checking.
    """
    try:
        # Input validation: Check if known_hash is a valid hexadecimal string
        if not re.match(r"^[0-9a-fA-F]+$", known_hash):
            raise ValueError("known_hash must be a valid hexadecimal string.")

        # Input validation: Check hash length based on algorithm
        hash_algorithm_enum = HashAlgorithm(hash_algorithm)  # Validate hash_algorithm is a valid enum value
        expected_length = {
            HashAlgorithm.SHA256: 64,
            HashAlgorithm.SHA384: 96,
            HashAlgorithm.SHA512: 128,
        }[hash_algorithm_enum]

        if len(known_hash) != expected_length:
            raise ValueError(f"known_hash must be {expected_length} characters long for {hash_algorithm}.")

        # Ensure certificate is bytes
        if isinstance(certificate_pem, str):
            certificate_pem = certificate_pem.encode('utf-8')

        # Load the certificate using cryptography library
        try:
            certificate = x509.load_pem_x509_certificate(certificate_pem, default_backend())
        except ValueError as e:
            logging.error(f"Error loading PEM certificate: {e}")
            return False  # Or try loading as DER if you want to support it

        # Choose the hashing algorithm
        if hash_algorithm_enum == HashAlgorithm.SHA256:
            digest = hashes.SHA256()
        elif hash_algorithm_enum == HashAlgorithm.SHA384:
            digest = hashes.SHA384()
        elif hash_algorithm_enum == HashAlgorithm.SHA512:
            digest = hashes.SHA512()
        else:
            # This should never happen because of the enum validation above, but included for safety
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}.  Only sha256, sha384, and sha512 are allowed.")

        # Hash the certificate
        hasher = hashes.Hash(digest, backend=default_backend())
        hasher.update(certificate_pem)  # Hash the raw PEM data
        cert_hash = hasher.finalize().hex()

        # Compare the hashes (case-insensitive, constant-time)
        return secrets.compare_digest(cert_hash.lower(), known_hash.lower())

    except ValueError as ve:
        logging.error(f"Invalid input: {ve}")
        return False
    except x509.InvalidVersion as ive:
        logging.error(f"Invalid certificate version: {ive}")
        return False
    except InvalidSignature as ise:
        logging.error(f"Invalid certificate signature: {ise}")
        return False
    except CryptoError as e:
        logging.error(f"Cryptography error: {e}")
        return False
    except Exception as e:
        logging.exception(f"Unexpected error during certificate validation: {e}")  # Log full traceback
        return False

