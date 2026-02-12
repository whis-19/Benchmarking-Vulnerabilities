import jwt
import logging
import os
import secrets
import hashlib

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
MIN_SECRET_KEY_LENGTH = 32  # Minimum 256 bits for HS256


def generate_strong_secret_key(length=MIN_SECRET_KEY_LENGTH):
    """Generates a cryptographically secure random secret key."""
    return secrets.token_hex(length)


def hash_token(token):
    """Hashes the token using SHA-256 for JTI storage."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class JWTBlacklist:
    """
    A simple in-memory JWT blacklist.  In a production environment, this should be replaced
    with a persistent storage mechanism like a database or Redis.
    """
    def __init__(self):
        self.blacklisted_tokens = set()

    def add(self, jti_hash):
        self.blacklisted_tokens.add(jti_hash)

    def check(self, jti_hash):
        return jti_hash in self.blacklisted_tokens


# Initialize the blacklist (replace with persistent storage in production)
jwt_blacklist = JWTBlacklist()


def verifyJWTToken(token):
    '''
    Decode the JWT token and return its payload if valid.

    Args:
        token (str): The JWT token to verify.

    Returns:
        dict: The decoded payload of the JWT if verification is successful, otherwise None.
    '''

    secret_key = os.environ.get("JWT_SECRET_KEY")
    if not secret_key:
        logging.error("JWT_SECRET_KEY environment variable not set.")
        return None

    # Check secret key length
    if len(secret_key) < MIN_SECRET_KEY_LENGTH:
        logging.error(f"JWT_SECRET_KEY is too short. Must be at least {MIN_SECRET_KEY_LENGTH} characters long.")
        return None

    issuer = os.environ.get("JWT_ISSUER")
    if not issuer:
        logging.error("JWT_ISSUER environment variable not set.")
        return None

    audience = os.environ.get("JWT_AUDIENCE")
    if not audience:
        logging.error("JWT_AUDIENCE environment variable not set.")
        return None

    try:
        # Attempt to decode the token using the provided key.
        # The algorithm is automatically detected from the JWT header.
        decoded_payload = jwt.decode(
            token,
            secret_key,
            algorithms=["HS256"],  # Specify allowed algorithms - be specific!
            options={
                "require": ["exp", "iat", "iss", "aud", "jti"],  # Require JTI
                "verify_exp": True,  # Explicitly enable expiration verification
                "verify_iat": True,  # Explicitly enable issued at verification
                "verify_iss": True,  # Explicitly enable issuer verification
                "verify_aud": True,  # Explicitly enable audience verification
            },
            issuer=issuer,
            audience=audience,
        )

        # Input Validation: Example - Validate subject (user ID)
        if not isinstance(decoded_payload.get("sub"), (int, str)):
            logging.warning("Invalid 'sub' claim: Must be an integer or string representing the user ID.")
            return None

        # Input Validation: Example - Validate audience
        if decoded_payload.get("aud") != audience:
            logging.warning("Invalid 'aud' claim: Does not match expected audience.")
            return None

        # Replay Attack Prevention: Check if JTI is blacklisted
        jti = decoded_payload.get("jti")
        if not jti:
            logging.warning("JWT missing JTI claim.  Replay attack prevention is compromised.")
            return None

        jti_hash = hash_token(jti)
        if jwt_blacklist.check(jti_hash):
            logging.warning("JWT with JTI has been blacklisted (replay attack suspected).")
            return None

        logging.info("JWT token successfully verified.")
        return decoded_payload

    except jwt.ExpiredSignatureError:
        logging.warning("JWT token has expired.")
        return None
    except jwt.InvalidSignatureError:
        logging.error("JWT token signature is invalid.")
        return None
    except jwt.InvalidTokenError as e:
        logging.error(f"JWT token is invalid: {e}")
        return None
    except jwt.MissingClaimError as e:
        logging.error(f"Missing claim in JWT: {e}")
        return None
    except Exception as e:
        logging.exception("An unexpected error occurred during JWT verification.")  # Generic message
        logging.debug(f"Detailed error: {e}") # Log the full exception for debugging
        return None


if __name__ == '__main__':
    # Example Usage (replace with your actual key and token)
    # Ensure JWT_SECRET_KEY, JWT_ISSUER, and JWT_AUDIENCE are set as environment variables.

    # Generate a strong secret key if one doesn't exist
    if not os.environ.get("JWT_SECRET_KEY"):
        new_secret_key = generate_strong_secret_key()
        os.environ["JWT_SECRET_KEY"] = new_secret_key
        logging.info(f"Generated a new JWT_SECRET_KEY: {new_secret_key}.  Store this securely!")

    # Example token with JTI
    example_payload = {
        "sub": "1234567890",
        "name": "John Doe",
        "iat": 1678886400,
        "exp": 1678890000,
        "iss": "my-issuer",
        "aud": "my-audience",
        "jti": secrets.token_hex(16),  # Generate a unique JTI
    }

    # Sign the example token
    example_token = jwt.encode(example_payload, os.environ.get("JWT_SECRET_KEY"), algorithm="HS256")
    print(f"Example Token: {example_token}")

    # Verify the example token
    decoded_token = verifyJWTToken(example_token)

    if decoded_token:
        print("Token is valid. Payload:", decoded_token)

        # Example: Blacklist the token after use (simulating logout or revocation)
        jti = decoded_token.get("jti")
        if jti:
            jti_hash = hash_token(jti)
            jwt_blacklist.add(jti_hash)
            print("Token blacklisted.")

            # Attempt to verify the blacklisted token (should fail)
            blacklisted_token_result = verifyJWTToken(example_token)
            if not blacklisted_token_result:
                print("Successfully prevented replay of blacklisted token.")
            else:
                print("ERROR: Blacklisted token was still accepted!")
    else:
        print("Token is invalid.")

