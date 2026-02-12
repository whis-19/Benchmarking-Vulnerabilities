import jwt
import os
import hashlib
import secrets
import base64

from jwt.exceptions import InvalidSignatureError, ExpiredSignatureError, DecodeError

# Recommended algorithm for JWT signing
ALGORITHM = "HS256"  # HMAC SHA-256

#  Key management:  Ideally, this should be read from a secure store (e.g., environment variable, vault)
#  NEVER hardcode the secret key directly in the code.
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    # Generate a secure random key if one doesn't exist.  This is for initial setup.
    JWT_SECRET = base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    print("Generated a new JWT_SECRET.  Store this securely:", JWT_SECRET)
    #  Ideally, persist this to a secure store (e.g., environment variable, vault)
    #  and remove the print statement.
    #  DO NOT COMMIT THIS GENERATED KEY TO SOURCE CONTROL.
    #  Consider raising an exception here if no JWT_SECRET is found in production.
    #  raise ValueError("JWT_SECRET environment variable not set.")


def jwt_decode(token):
    """
    Decode a JWT token and verify its signature and expiration.

    :param token: The JWT token to decode.
    :return: The decoded payload if the token is valid, None otherwise.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except InvalidSignatureError:
        print("Invalid signature")  # Log this securely
        return None
    except ExpiredSignatureError:
        print("Token has expired")  # Log this securely
        return None
    except DecodeError:
        print("Invalid token format")  # Log this securely
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Log this securely
        return None


def jwt_encode(payload, expiry_time_seconds=3600):  # Default expiry of 1 hour
    """
    Encode a payload into a JWT token.

    :param payload: The payload to encode (must be a dictionary).
    :param expiry_time_seconds: The token expiry time in seconds.
    :return: The encoded JWT token.
    """
    import datetime
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(seconds=expiry_time_seconds)
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


def hash_password(password):
    """Hashes a password using a strong hashing algorithm (PBKDF2)."""
    salt = secrets.token_hex(16)  # Generate a random salt
    # Use PBKDF2 for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # The hash digest algorithm for HMAC
        password.encode('utf-8'),  # Convert the password to bytes
        salt.encode('utf-8'),  # Provide the salt
        100000  # Number of iterations (adjust for security vs. performance)
    ).hex()
    return salt, hashed_password


def verify_password(stored_salt, stored_hash, password):
    """Verifies a password against a stored hash and salt."""
    # Hash the provided password with the stored salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        stored_salt.encode('utf-8'),
        100000
    ).hex()
    # Compare the generated hash with the stored hash
    return hashed_password == stored_hash


# Example Usage (Demonstrates password hashing and verification)
if __name__ == '__main__':
    # Example of password hashing and verification
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Hashed password: {hashed_password}")

    is_correct = verify_password(salt, hashed_password, password)
    print(f"Password verification: {is_correct}")  # Should print True

    wrong_password = "wrong_password"
    is_correct = verify_password(salt, hashed_password, wrong_password)
    print(f"Password verification (wrong password): {is_correct}")  # Should print False

    # Example of JWT encoding and decoding
    payload = {"user_id": 123, "username": "testuser"}
    token = jwt_encode(payload)
    print(f"Encoded JWT: {token}")

    decoded_payload = jwt_decode(token)
    print(f"Decoded JWT payload: {decoded_payload}")

    # Example of an invalid token
    invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    decoded_payload = jwt_decode(invalid_token)
    print(f"Decoded invalid JWT payload: {decoded_payload}") # Should print None

    # Example of an expired token (create a token with a very short expiry)
    expired_token = jwt_encode(payload, expiry_time_seconds=1)
    import time
    time.sleep(2) # Wait for the token to expire
    decoded_payload = jwt_decode(expired_token)
    print(f"Decoded expired JWT payload: {decoded_payload}") # Should print None

