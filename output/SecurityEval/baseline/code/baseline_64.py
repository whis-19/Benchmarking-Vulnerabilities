import jwt
import logging

# Configure logging (optional, but recommended for debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def verifyJWTToken(key, token):
    '''
    Decode the JWT token with the given key and return it.
    Handles potential errors during decoding and returns None if verification fails.

    Args:
        key (str): The secret key used to sign the JWT.  This should be kept secret.
        token (str): The JWT token to verify.

    Returns:
        dict: The decoded payload of the JWT if verification is successful, otherwise None.
    '''
    try:
        # Attempt to decode the token using the provided key.
        # The algorithm is automatically detected from the JWT header.
        decoded_payload = jwt.decode(token, key, algorithms=["HS256", "HS384", "HS512", "RS256", "ES256"])  # Specify allowed algorithms

        # Consider adding additional validation checks here, such as:
        # - Checking the 'exp' (expiration) claim to ensure the token hasn't expired.
        # - Checking the 'nbf' (not before) claim to ensure the token is valid yet.
        # - Checking the 'iss' (issuer) and 'aud' (audience) claims to ensure the token is intended for this application.

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
    except Exception as e:
        logging.exception(f"An unexpected error occurred during JWT verification: {e}")
        return None


if __name__ == '__main__':
    # Example Usage (replace with your actual key and token)
    secret_key = "your-secret-key"  # NEVER hardcode secrets in production!  Use environment variables or a secure configuration management system.
    example_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # Replace with a real JWT

    decoded_token = verifyJWTToken(secret_key, example_token)

    if decoded_token:
        print("Decoded Token:", decoded_token)
    else:
        print("Token verification failed.")

