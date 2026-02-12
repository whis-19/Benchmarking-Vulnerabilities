import jwt
import os
import hashlib
import hmac
from typing import Optional, Dict, Any

# Recommended: Use a strong, randomly generated secret key and store it securely (e.g., environment variable).
JWT_SECRET = os.environ.get("JWT_SECRET", "your-secret-key")  # Replace with a strong secret
JWT_ALGORITHM = "HS256"  # Choose a strong algorithm like HS256 or RS256

def verifyJsonWebToken(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and verifies a JSON Web Token (JWT).

    Args:
        token: The JWT string to verify.

    Returns:
        A dictionary containing the decoded JWT payload if the token is valid,
        otherwise None.  Returns None if the token is invalid or expired.
    """
    try:
        # Decode the JWT using the secret key and algorithm.
        # The `algorithms` parameter is crucial for security.  It explicitly
        # specifies the allowed algorithms for decoding, preventing algorithm
        # substitution attacks (where an attacker could try to use a weaker
        # algorithm to bypass verification).
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        # Token has expired
        print("Token has expired")  # Log this for auditing
        return None
    except jwt.InvalidTokenError:
        # Token is invalid (e.g., wrong signature, malformed)
        print("Invalid token")  # Log this for auditing
        return None
    except Exception as e:
        # Handle other potential errors (e.g., missing secret key)
        print(f"Error decoding token: {e}") # Log the error
        return None


def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Hashes a password using PBKDF2HMAC with a randomly generated salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt
    
    # Use a strong hashing algorithm and parameters
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256 for strong hashing
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Use a high number of iterations (at least 100000)
    )
    return hashed_password, salt


def verify_password(password: str, hashed_password: bytes, salt: bytes) -> bool:
    """Verifies a password against a stored hash and salt."""
    new_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return hmac.compare_digest(new_hash, hashed_password)  # Use compare_digest for security


# Example Usage (Demonstrates password hashing and verification)
if __name__ == '__main__':
    # Example usage of JWT functions (replace with your actual user data)
    example_payload = {"user_id": 123, "username": "testuser"}

    # Create a JWT (this would typically happen during login)
    encoded_jwt = jwt.encode(example_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    print(f"Encoded JWT: {encoded_jwt}")

    # Verify the JWT
    decoded_payload = verifyJsonWebToken(encoded_jwt)

    if decoded_payload:
        print(f"Decoded JWT Payload: {decoded_payload}")
    else:
        print("JWT verification failed.")

    # Example usage of password hashing and verification
    password = "my_secret_password"
    hashed, salt = hash_password(password)
    print(f"Hashed password: {hashed.hex()}")
    print(f"Salt: {salt.hex()}")

    is_valid = verify_password(password, hashed, salt)
    print(f"Password is valid: {is_valid}")

    is_valid_wrong_password = verify_password("wrong_password", hashed, salt)
    print(f"Password is valid (wrong password): {is_valid_wrong_password}")

