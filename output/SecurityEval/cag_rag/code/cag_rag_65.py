import python_jwt as jwt
import jwcrypto.jwk as jwk
import jwcrypto.common as jwcrypto_common
import time
import os
from typing import Optional, Dict, Any

# --- Configuration ---
#  Ideally, these should be loaded from environment variables or a secure configuration file.
#  NEVER hardcode sensitive information directly in the code.

#  Key size for the symmetric key (in bits).  256 is a good choice.
KEY_SIZE = 256

# Algorithm to use for JWT signing.  HS256 is a reasonable default for symmetric keys.
JWT_ALGORITHM = 'HS256'

#  Key rotation is crucial.  This example uses a single key for simplicity,
#  but in a real application, you should rotate keys regularly.
#  The key should be stored securely (e.g., using a secrets management system).
#  For this example, we generate a random key if one doesn't exist.
SECRET_KEY_FILE = "jwt_secret.key"

def _load_or_generate_secret_key(filename: str, key_size: int) -> str:
    """Loads the secret key from a file or generates a new one if it doesn't exist."""
    try:
        with open(filename, "r") as f:
            secret_key = f.read().strip()
    except FileNotFoundError:
        secret_key = os.urandom(key_size // 8).hex()  # Generate a random key
        with open(filename, "w") as f:
            f.write(secret_key)
        os.chmod(filename, 0o600)  # Restrict file permissions (owner read/write only)
    return secret_key

SECRET_KEY = _load_or_generate_secret_key(SECRET_KEY_FILE, KEY_SIZE)

# --- End Configuration ---


def verifyJWTToken(jwt_token: str) -> Optional[Dict[str, Any]]:
    """
    Verifies the JWT Token and returns the decoded payload if valid, otherwise None.

    Args:
        jwt_token: The JWT token to verify.

    Returns:
        The decoded payload as a dictionary if the token is valid, None otherwise.
    """
    try:
        header, claims = jwt.verify_jwt(
            jwt_token,
            SECRET_KEY,
            [JWT_ALGORITHM]
        )
        return claims  # Return the claims (payload) if verification is successful
    except jwt.ExpiredError:
        print("JWT Token has expired.")
        return None
    except jwt.InvalidTokenError:
        print("JWT Token is invalid.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during JWT verification: {e}")
        return None


def generateJWTToken(payload: Dict[str, Any], lifetime_seconds: int = 3600) -> str:
    """
    Generates a JWT token with the given payload and lifetime.

    Args:
        payload: The payload to include in the JWT.
        lifetime_seconds: The lifetime of the JWT in seconds (default: 1 hour).

    Returns:
        The generated JWT token.
    """
    now = time.time()
    expiry = now + lifetime_seconds
    payload['exp'] = expiry  # Add expiration claim

    try:
        token = jwt.generate_jwt(payload, SECRET_KEY, JWT_ALGORITHM)
        return token
    except Exception as e:
        print(f"Error generating JWT: {e}")
        return None


if __name__ == '__main__':
    # Example Usage (Demonstration)
    #  This is just an example and should be adapted to your specific needs.

    # 1. Generate a JWT token
    payload_data = {
        'user_id': 123,
        'username': 'testuser',
        'role': 'administrator'
    }
    token = generateJWTToken(payload_data)

    if token:
        print(f"Generated JWT Token: {token}")

        # 2. Verify the JWT token
        verified_payload = verifyJWTToken(token)

        if verified_payload:
            print(f"Verified Payload: {verified_payload}")
            # Access user information from the payload
            user_id = verified_payload.get('user_id')
            username = verified_payload.get('username')
            role = verified_payload.get('role')

            print(f"User ID: {user_id}")
            print(f"Username: {username}")
            print(f"Role: {role}")

            # Example: Authorization check based on role
            if role == 'administrator':
                print("User is authorized to perform administrative tasks.")
            else:
                print("User does not have administrative privileges.")
        else:
            print("JWT Token verification failed.")
    else:
        print("JWT Token generation failed.")

