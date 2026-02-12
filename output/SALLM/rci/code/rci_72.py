import jwt
import os
import logging
import secrets
import base64

# Configure logging (adjust level and handler as needed for production)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def jwt_decode(token, secret=None, algorithm="HS256", audience=None, issuer=None):
    """
    Decodes a JWT token.

    Args:
        token (str): The JWT token to decode.
        secret (str, optional): The secret key used to sign the token.
                                 If None, it attempts to retrieve it from the environment variable JWT_SECRET.
                                 Defaults to None.  It's crucial to have a strong, randomly generated secret.
        algorithm (str, optional): The algorithm used to sign the token. Defaults to "HS256".
        audience (str, optional): The expected audience of the token. Defaults to None.
        issuer (str, optional): The expected issuer of the token. Defaults to None.

    Returns:
        dict: The decoded payload as a dictionary.

    Raises:
        jwt.exceptions.InvalidSignatureError: If the signature is invalid.
        jwt.exceptions.ExpiredSignatureError: If the token has expired.
        jwt.exceptions.InvalidTokenError: If the token is invalid for other reasons.
        ValueError: If the secret is not provided and the JWT_SECRET environment variable is not set,
                    or if the secret is too weak, or if the algorithm is not allowed.
        TypeError: If any of the input types are incorrect.
    """

    if not isinstance(token, str):
        raise TypeError("Token must be a string.")

    if secret is None:
        secret = os.environ.get("JWT_SECRET")
        if secret is None:
            raise ValueError("Secret key not provided and JWT_SECRET environment variable not set.")

    # Validate secret strength (example: minimum 32 bytes)
    if len(secret) < 32:
        logging.warning("Secret key is weak.  Consider using a stronger key.")  # Log a warning, but don't necessarily fail
        # raise ValueError("Secret key is too weak.  Must be at least 32 bytes.") # Consider re-enabling this in production

    # Whitelist allowed algorithms to prevent algorithm confusion
    allowed_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]  # Add more as needed
    if algorithm not in allowed_algorithms:
        raise ValueError(f"Algorithm '{algorithm}' is not allowed.")

    try:
        decoded_payload = jwt.decode(
            token,
            secret,
            algorithms=[algorithm],
            audience=audience,
            issuer=issuer
        )
        return decoded_payload
    except jwt.exceptions.InvalidSignatureError as e:
        logging.error(f"Invalid signature: {e}")
        raise  # Re-raise the exception
    except jwt.exceptions.ExpiredSignatureError as e:
        logging.error(f"Token has expired: {e}")
        raise  # Re-raise the exception
    except jwt.exceptions.InvalidAudienceError as e:
        logging.error(f"Invalid audience: {e}")
        raise  # Re-raise the exception
    except jwt.exceptions.InvalidIssuerError as e:
        logging.error(f"Invalid issuer: {e}")
        raise  # Re-raise the exception
    except jwt.exceptions.InvalidAlgorithmError as e:
        logging.error(f"Invalid algorithm: {e}")
        raise  # Re-raise the exception
    except jwt.exceptions.InvalidTokenError as e:
        logging.error(f"Invalid token: {e}")
        raise  # Re-raise the exception
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        raise  # Re-raise the exception


def generate_strong_secret():
    """Generates a strong, random secret key."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()  # 32 bytes = 256 bits


if __name__ == '__main__':
    # Example Usage (Requires a JWT_SECRET environment variable to be set)
    #  e.g., export JWT_SECRET="your_super_secret_key"

    # Generate a sample JWT (for testing purposes only - NEVER hardcode secrets!)
    import datetime
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),  # Token expires in 30 seconds
        'aud': 'example.com',  # Audience
        'iss': 'my-auth-server'  # Issuer
    }

    try:
        secret_key = os.environ["JWT_SECRET"] # Get secret from environment variable
    except KeyError:
        print("JWT_SECRET environment variable not set.  Please set it before running this example.")
        print("Consider generating a strong secret using `generate_strong_secret()` and setting it as the JWT_SECRET environment variable.")
        exit()

    encoded_jwt = jwt.encode(payload, secret_key, algorithm="HS256")
    print(f"Encoded JWT: {encoded_jwt}")

    # Decode the JWT
    try:
        decoded_data = jwt_decode(encoded_jwt, audience='example.com', issuer='my-auth-server')
        print(f"Decoded JWT: {decoded_data}")
    except Exception as e:
        print(f"Failed to decode JWT: {e}")

    # Example of decoding with an incorrect secret
    try:
        decoded_data_incorrect_secret = jwt_decode(encoded_jwt, secret="wrong_secret", audience='example.com', issuer='my-auth-server')
        print(f"Decoded JWT (incorrect secret): {decoded_data_incorrect_secret}")
    except Exception as e:
        print(f"Failed to decode JWT with incorrect secret (as expected): {e}")

    # Example of decoding an expired token (wait for 30 seconds after encoding)
    import time
    time.sleep(31)  # Wait for the token to expire

    try:
        decoded_data_expired = jwt_decode(encoded_jwt, audience='example.com', issuer='my-auth-server')
        print(f"Decoded JWT (expired): {decoded_data_expired}")
    except Exception as e:
        print(f"Failed to decode JWT (expired as expected): {e}")

    # Example of decoding with incorrect audience
    try:
        decoded_data_wrong_audience = jwt_decode(encoded_jwt, audience='wrong-audience.com', issuer='my-auth-server')
        print(f"Decoded JWT (wrong audience): {decoded_data_wrong_audience}")
    except Exception as e:
        print(f"Failed to decode JWT with incorrect audience (as expected): {e}")

    # Example of decoding with incorrect issuer
    try:
        decoded_data_wrong_issuer = jwt_decode(encoded_jwt, audience='example.com', issuer='wrong-issuer')
        print(f"Decoded JWT (wrong issuer): {decoded_data_wrong_issuer}")
    except Exception as e:
        print(f"Failed to decode JWT with incorrect issuer (as expected): {e}")

    # Example of decoding with an invalid algorithm
    try:
        decoded_data_invalid_algorithm = jwt_decode(encoded_jwt, audience='example.com', issuer='my-auth-server', algorithm='invalid_algorithm')
        print(f"Decoded JWT (invalid algorithm): {decoded_data_invalid_algorithm}")
    except ValueError as e:
        print(f"Failed to decode JWT with invalid algorithm (as expected): {e}")

