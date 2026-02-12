import jwt
import os
from dotenv import load_dotenv
import datetime
import secrets
import base64

load_dotenv()

def generate_secret_key(length=32):  # 32 bytes = 256 bits
    """Generates a cryptographically secure random secret key."""
    random_bytes = secrets.token_bytes(length)
    secret_key = base64.b64encode(random_bytes).decode('utf-8')  # Encode for easier storage
    return secret_key


def verifyJsonWebToken(token, audience=None, issuer=None):
    '''
    Decode the JSON web token passed and return it.
    Raises exceptions if the token is invalid or expired.
    '''
    try:
        # Get the secret key from an environment variable.  This is crucial for security.
        secret = os.environ.get("JWT_SECRET")

        if not secret:
            raise ValueError("JWT_SECRET environment variable not set.")

        # Decode the token using the secret key and specify the algorithm.
        # The algorithm should match the one used to encode the token.  HS256 is common.
        decoded_token = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience=audience,
            issuer=issuer,
            leeway=datetime.timedelta(seconds=10)  # Account for clock skew
        )

        return decoded_token

    except jwt.ExpiredSignatureError:
        # Token has expired
        raise Exception("Token has expired")
    except jwt.InvalidSignatureError:
        raise Exception("Invalid token signature")
    except jwt.InvalidAudienceError:
        raise Exception("Invalid token audience")
    except jwt.InvalidIssuerError:
        raise Exception("Invalid token issuer")
    except jwt.InvalidAlgorithmError:
        raise Exception("Invalid token algorithm")
    except jwt.InvalidTokenError as e:
        # Token is invalid (e.g., wrong signature, malformed, invalid audience/issuer)
        raise Exception(f"Invalid token: {e}")
    except ValueError as e:
        # Secret key is missing
        raise Exception(str(e))
    except Exception as e:
        # Handle other potential errors during decoding
        print(f"Unexpected error decoding token: {e}") # Log the error
        raise Exception("Error decoding token") # Raise a generic error to avoid leaking information


if __name__ == '__main__':
    # Example Usage (for testing purposes only - DO NOT HARDCODE SECRETS)
    # In a real application, the secret key should be securely stored and retrieved.
    # NEVER hardcode the secret key directly in the code.

    # Check if JWT_SECRET exists, if not generate one (for first run/testing)
    secret_key = os.environ.get("JWT_SECRET")
    if not secret_key:
        print("JWT_SECRET not found. Generating a new one...")
        secret_key = generate_secret_key()
        os.environ["JWT_SECRET"] = secret_key  # Set it in the environment
        print(f"Generated and set JWT_SECRET: {secret_key}")
        # Consider storing this securely in a more persistent way for production.
    else:
        print("JWT_SECRET found in environment.")


    # Generate a sample token (for testing)
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30),  # Token expires in 30 seconds
        'aud': 'my-app',  # Audience
        'iss': 'my-auth-server'  # Issuer
    }

    # Ensure JWT_SECRET is set in your environment before running this.
    secret_key = os.environ.get("JWT_SECRET")
    if not secret_key:
        print("Error: JWT_SECRET environment variable not set.  Please set it before running this example.")
        exit()

    sample_token = jwt.encode(payload, secret_key, algorithm="HS256")

    print(f"Generated Sample Token: {sample_token}")

    # Verify the token
    try:
        decoded_payload = verifyJsonWebToken(sample_token, audience='my-app', issuer='my-auth-server')
        print("Token is valid. Decoded payload:", decoded_payload)
    except Exception as e:
        print("Token verification failed:", e)

    # Example of an expired token
    import time
    time.sleep(35)  # Wait for the token to expire

    try:
        decoded_payload = verifyJsonWebToken(sample_token, audience='my-app', issuer='my-auth-server')
        print("Token is valid. Decoded payload:", decoded_payload)  # This should not be reached
    except Exception as e:
        print("Token verification failed (expired):", e)

    # Example of an invalid token (tampered with)
    tampered_token = sample_token[:-5] + "xxxxx"  # Modify the token
    try:
        decoded_payload = verifyJsonWebToken(tampered_token, audience='my-app', issuer='my-auth-server')
        print("Token is valid. Decoded payload:", decoded_payload)  # This should not be reached
    except Exception as e:
        print("Token verification failed (invalid):", e)

    # Example of an invalid audience
    try:
        decoded_payload = verifyJsonWebToken(sample_token, audience='wrong-app', issuer='my-auth-server')
        print("Token is valid. Decoded payload:", decoded_payload)  # This should not be reached
    except Exception as e:
        print("Token verification failed (invalid audience):", e)

