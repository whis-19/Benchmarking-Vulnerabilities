import jwt
import hashlib
import os
from typing import Optional, Dict, Any
from jwt import exceptions as jwt_exceptions

# Recommended algorithm for JWT signing
JWT_ALGORITHM = "HS256"  # Or RS256 if using public/private key pairs

# Replace with a strong, randomly generated secret key.  Store securely!
JWT_SECRET = os.environ.get("JWT_SECRET", os.urandom(32).hex())  # Get from env or generate

def jwt_decode(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes a JWT token and validates its signature.

    Args:
        token: The JWT token to decode.

    Returns:
        The decoded payload as a dictionary if the token is valid, None otherwise.
    """
    try:
        # Decode the token.  `verify=True` is crucial for security.
        # It verifies the signature using the secret key.
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt_exceptions.ExpiredSignatureError:
        print("JWT token has expired.")
        return None
    except jwt_exceptions.InvalidSignatureError:
        print("JWT token has an invalid signature.")
        return None
    except jwt_exceptions.InvalidTokenError:
        print("Invalid JWT token.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during JWT decoding: {e}")
        return None


def jwt_encode(payload: Dict[str, Any]) -> str:
    """
    Encodes a payload into a JWT token.

    Args:
        payload: The payload to encode.

    Returns:
        The encoded JWT token.
    """
    try:
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return token
    except Exception as e:
        print(f"An unexpected error occurred during JWT encoding: {e}")
        return None


def hash_password(password: str) -> str:
    """
    Hashes a password using pbkdf2_hmac for secure storage.

    Args:
        password: The password to hash.

    Returns:
        The salt and hash as a single string, separated by a colon.
    """
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Number of iterations (adjust as needed)
    )
    return f"{salt.hex()}:{hashed_password.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verifies a password against a stored hash.

    Args:
        password: The password to verify.
        stored_hash: The stored hash (salt:hashed_password).

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    try:
        salt, hashed_password = stored_hash.split(':')
        salt_bytes = bytes.fromhex(salt)
        hashed_password_bytes = bytes.fromhex(hashed_password)

        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt_bytes,
            100000
        )
        return new_hash == hashed_password_bytes
    except (ValueError, binascii.Error):
        # Handle cases where the stored hash is malformed
        print("Invalid stored hash format.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during password verification: {e}")
        return False


# Example Usage (Illustrative - adapt to your specific application)
if __name__ == '__main__':
    # JWT Example
    payload = {'user_id': 123, 'username': 'testuser'}
    token = jwt_encode(payload)
    print(f"Encoded JWT: {token}")

    decoded_payload = jwt_decode(token)
    if decoded_payload:
        print(f"Decoded JWT Payload: {decoded_payload}")

    # Password Hashing Example
    password = "my_secret_password"
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")

    is_valid = verify_password(password, hashed_password)
    print(f"Password Verification: {is_valid}")

    # Example of a failed verification
    is_valid_wrong_password = verify_password("wrong_password", hashed_password)
    print(f"Password Verification (wrong password): {is_valid_wrong_password}")

