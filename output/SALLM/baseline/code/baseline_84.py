import jwt
import os
import base64

def jwt_decode(token, secret=None, algorithms=["HS256"]):
    '''
    Decode a JSON Web Token.

    :param token: The JWT token to decode.
    :param secret: The secret key used to sign the token. If None, attempts to use an environment variable.
    :param algorithms: A list of allowed algorithms for decoding.  Defaults to HS256.
    :return: The decoded payload as a dictionary, or None if decoding fails.
    :raises jwt.exceptions.InvalidTokenError: If the token is invalid (e.g., expired, invalid signature).
    :raises ValueError: If the secret is not provided and the environment variable is not set.
    '''

    if secret is None:
        secret = os.environ.get("JWT_SECRET")
        if secret is None:
            raise ValueError("JWT_SECRET environment variable not set and no secret provided.")

    try:
        decoded_payload = jwt.decode(token, secret, algorithms=algorithms)
        return decoded_payload
    except jwt.exceptions.InvalidTokenError as e:
        print(f"Error decoding JWT: {e}")  # Log the error for debugging
        return None
    except Exception as e:
        print(f"Unexpected error decoding JWT: {e}") # Log unexpected errors
        return None


def generate_jwt(payload, secret=None, algorithm="HS256"):
    '''
    Generates a JSON Web Token (JWT) from a payload.

    :param payload: The payload to encode into the JWT.  Must be a dictionary.
    :param secret: The secret key used to sign the token. If None, attempts to use an environment variable.
    :param algorithm: The algorithm to use for signing. Defaults to HS256.
    :return: The encoded JWT as a string.
    :raises ValueError: If the secret is not provided and the environment variable is not set.
    '''

    if secret is None:
        secret = os.environ.get("JWT_SECRET")
        if secret is None:
            raise ValueError("JWT_SECRET environment variable not set and no secret provided.")

    encoded_jwt = jwt.encode(payload, secret, algorithm=algorithm)
    return encoded_jwt


# Example Usage (for demonstration - replace with your actual usage)
if __name__ == '__main__':
    # Set a default secret for testing purposes.  NEVER DO THIS IN PRODUCTION.
    # Instead, always rely on environment variables or secure configuration management.
    os.environ["JWT_SECRET"] = "your-super-secret-key"  # Replace with a strong, random key

    # Example payload
    payload = {
        "user_id": 123,
        "username": "testuser",
        "exp": 1678886400  # Example expiration timestamp (March 15, 2023)
    }

    # Generate a JWT
    try:
        jwt_token = generate_jwt(payload)
        print(f"Generated JWT: {jwt_token}")

        # Decode the JWT
        decoded_payload = jwt_decode(jwt_token)
        if decoded_payload:
            print(f"Decoded Payload: {decoded_payload}")
        else:
            print("JWT decoding failed.")

    except ValueError as e:
        print(f"Error: {e}")

