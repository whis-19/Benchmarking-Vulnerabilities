import python_jwt as jwt
import jwcrypto.jwk as jwk
import jwcrypto.common as jwcrypto_common
import time
import os
from typing import Optional, Dict, Any

# --- Key Management ---
# Generate a new RSA key pair if one doesn't exist.  Store securely.
# NEVER hardcode keys.  Use environment variables, key vaults, or secure storage.
KEY_FILE = "jwt_key.pem"

def generate_key_pair():
    """Generates a new RSA key pair and saves it to a file."""
    key = jwk.JWK.generate(kty='RSA', size=2048)
    with open(KEY_FILE, "w") as f:
        f.write(key.export_private())
    return key

def load_key():
    """Loads the RSA key from the file."""
    try:
        with open(KEY_FILE, "r") as f:
            key_data = f.read()
            key = jwk.JWK.from_pem(key_data.encode('utf-8'))
            return key
    except FileNotFoundError:
        print("Key file not found. Generating a new key pair.")
        return generate_key_pair()
    except Exception as e:
        print(f"Error loading key: {e}. Generating a new key pair.")
        os.remove(KEY_FILE) # Remove potentially corrupted key file
        return generate_key_pair()

key = load_key()


def verifyJWTToken(jwt_token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies the JWT Token and returns the decoded payload if valid, otherwise None.

    Args:
        jwt_token: The JWT token string.

    Returns:
        The decoded payload as a dictionary if the token is valid, None otherwise.
    """
    try:
        # Use the public key for verification.  Crucially important.
        decoded_payload = jwt.verify_jwt(jwt_token, key, ['RS256'], leeway=60)  # Allow for clock skew
        return decoded_payload
    except jwt.ExpiredTokenError:
        print("JWT Token has expired.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid JWT Token: {e}")
        return None
    except Exception as e:
        print(f"Error verifying JWT Token: {e}")
        return None


def generateJWTToken(payload: Dict[str, Any], expiration_time: int = 3600) -> str:
    """
    Generates a JWT token with the given payload and expiration time.

    Args:
        payload: The payload to include in the JWT.
        expiration_time: The expiration time in seconds (default: 1 hour).

    Returns:
        The generated JWT token.
    """
    # Add expiration time to the payload
    payload['exp'] = int(time.time()) + expiration_time

    # Sign the token using the private key.  Keep the private key SECRET.
    token = jwt.generate_jwt(payload, key, 'RS256')
    return token


if __name__ == '__main__':
    # Example Usage
    payload = {'user_id': 123, 'username': 'testuser'}
    token = generateJWTToken(payload)
    print(f"Generated JWT Token: {token}")

    decoded_payload = verifyJWTToken(token)
    if decoded_payload:
        print(f"Decoded Payload: {decoded_payload}")
    else:
        print("Token verification failed.")

    # Example of an expired token
    expired_payload = {'user_id': 456, 'username': 'olduser'}
    expired_token = generateJWTToken(expired_payload, expiration_time=-1)  # Expired immediately
    print(f"Generated Expired JWT Token: {expired_token}")

    decoded_expired_payload = verifyJWTToken(expired_token)
    if decoded_expired_payload:
        print(f"Decoded Expired Payload: {decoded_expired_payload}")
    else:
        print("Expired token verification failed as expected.")

