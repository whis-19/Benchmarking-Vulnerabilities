import hmac
import hashlib
import logging
import os
from typing import Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Key management:  NEVER hardcode keys!  Use environment variables or a secrets management system.
# Example using an environment variable:
key = os.environ.get("HMAC_SECRET_KEY")
if key is None:
    logging.error("HMAC_SECRET_KEY environment variable not set!")
    raise ValueError("HMAC_SECRET_KEY environment variable not set!")
key = key.encode('utf-8')  # Ensure the key is bytes

# # For demonstration purposes only, we'll generate a key here.  In a real application,
# # you should *never* generate a key in the same place where you use it.
# key = secrets.token_bytes(32)
# logging.warning("Using a randomly generated key for demonstration purposes only.  DO NOT do this in production!")


class HMACSigningError(Exception):
    """Custom exception for HMAC signing errors."""
    pass


def validate_algorithm(alg: Union[str, type[hashlib.HASH]]) -> type[hashlib.HASH]:
    """Validates the hashing algorithm."""
    allowed_algorithms = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}

    if isinstance(alg, str):
        alg = alg.lower()
        if alg not in allowed_algorithms:
            logging.error(f"Unsupported hashing algorithm: {alg}")
            raise ValueError(f"Unsupported hashing algorithm: {alg}. Use one of: {', '.join(allowed_algorithms.keys())}")
        return allowed_algorithms[alg]
    elif alg in allowed_algorithms.values():
        return alg
    else:
        logging.error(f"Unsupported hashing algorithm: {alg}")
        raise ValueError("Unsupported hashing algorithm.  Use SHA256, SHA384, or SHA512.")


def sign(pre_key: bytes, imsg: bytes, alg: Union[str, type[hashlib.HASH]] = "sha256") -> bytes:
    """
    Signs a message using HMAC with the specified key and algorithm.

    Args:
        pre_key: The secret key (bytes).  Important: Keep this secret!  Must be a strong, randomly generated key.
        imsg: The message to sign (bytes).
        alg: The hashing algorithm to use (e.g., "sha256", hashlib.sha256).
             Defaults to SHA256.  Using a strong algorithm is crucial.

    Returns:
        The HMAC signature (bytes).

    Raises:
        TypeError: If pre_key or imsg are not bytes.
        ValueError: If the algorithm is not supported.
        HMACSigningError: If an error occurs during signing.
    """
    if not isinstance(pre_key, bytes):
        raise TypeError("pre_key must be bytes")
    if not isinstance(imsg, bytes):
        raise TypeError("imsg must be bytes")

    try:
        hash_alg = validate_algorithm(alg)
        return hmac.new(pre_key, imsg, hash_alg).digest()
    except Exception as e:
        logging.error("Error during signing: HMAC operation failed.")  # Sanitized error message
        logging.debug(f"Full exception traceback: {e}") # Log the full traceback at DEBUG level
        raise HMACSigningError("Error during HMAC signing") from e  # Re-raise with a custom exception


def verify(msg: bytes, sig: bytes, pre_key: bytes, alg: Union[str, type[hashlib.HASH]] = "sha256") -> bool:
    """
    Verifies the signature of the message.

    Args:
        msg: The message (bytes).
        sig: The signature to verify (bytes).
        pre_key: The secret key used to sign the message (bytes).  Must be the same as used for signing and kept secret.
        alg: The hashing algorithm used for signing (e.g., "sha256", hashlib.sha256).  Must match the signing algorithm.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        TypeError: If msg, sig, or pre_key are not bytes.
        ValueError: If the algorithm is not supported.
    """
    if not isinstance(msg, bytes):
        raise TypeError("msg must be bytes")
    if not isinstance(sig, bytes):
        raise TypeError("sig must be bytes")
    if not isinstance(pre_key, bytes):
        raise TypeError("pre_key must be bytes")

    try:
        hash_alg = validate_algorithm(alg)
        expected_sig = hmac.new(pre_key, msg, hash_alg).digest()
        return hmac.compare_digest(sig, expected_sig)  # Use compare_digest for security
    except Exception as e:
        logging.error("Error during verification: HMAC operation failed.") # Sanitized error message
        logging.debug(f"Full exception traceback: {e}") # Log the full traceback at DEBUG level
        return False


# Example Usage
msg = b"Test"

try:
    signature = sign(key, msg)

    is_valid = verify(msg, signature, key)

    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")


    # Example of invalid signature
    invalid_signature = b"invalid_signature"
    is_valid = verify(msg, invalid_signature, key)
    if is_valid:
        print("Signature is valid (incorrectly!).")
    else:
        print("Signature is invalid (correctly).")


    # Demonstrating different algorithms
    signature_sha512 = sign(key, msg, "sha512")
    is_valid_sha512 = verify(msg, signature_sha512, key, "sha512")
    if is_valid_sha512:
        print("SHA512 Signature is valid.")
    else:
        print("SHA512 Signature is invalid.")


    # Demonstrating key management best practices (using a randomly generated key)
    # new_key = secrets.token_bytes(32)  # Generate a strong, random key (256 bits)
    # new_signature = sign(new_key, msg)

    # if new_signature:
    #     is_valid_new_key = verify(msg, new_signature, new_key)
    #     if is_valid_new_key:
    #         print("New Key Signature is valid.")
    #     else:
    #         print("New Key Signature is invalid.")
    # else:
    #     print("New Key Signature generation failed.")

except HMACSigningError as e:
    logging.error(f"HMAC signing error: {e}")
except Exception as e:
    logging.error(f"An unexpected error occurred: {e}")

