import jwt
import os

def jwt_decode(token, secret=None, algorithm="HS256"):
    """
    Decodes a JWT token.

    Args:
        token (str): The JWT token to decode.
        secret (str, optional): The secret key used to sign the token. 
                                 If None, it attempts to retrieve it from the environment variable JWT_SECRET.
                                 Defaults to None.  It's crucial to have a strong, randomly generated secret.
        algorithm (str, optional): The algorithm used to sign the token. Defaults to "HS256".

    Returns:
        dict: The decoded payload as a dictionary, or None if decoding fails.

    Raises:
        jwt.exceptions.InvalidSignatureError: If the signature is invalid.
        jwt.exceptions.ExpiredSignatureError: If the token has expired.
        jwt.exceptions.InvalidTokenError: If the token is invalid for other reasons.
        ValueError: If the secret is not provided and the JWT_SECRET environment variable is not set.
    """

    if secret is None:
        secret = os.environ.get("JWT_SECRET")
        if secret is None:
            raise ValueError("Secret key not provided and JWT_SECRET environment variable not set.")

    try:
        decoded_payload = jwt.decode(token, secret, algorithms=[algorithm])
        return decoded_payload
    except jwt.exceptions.InvalidSignatureError:
        print("Invalid signature.")
        return None
    except jwt.exceptions.ExpiredSignatureError:
        print("Token has expired.")
        return None
    except jwt.exceptions.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example Usage (Requires a JWT_SECRET environment variable to be set)
    #  e.g., export JWT_SECRET="your_super_secret_key"

    # Generate a sample JWT (for testing purposes only - NEVER hardcode secrets!)
    import datetime
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)  # Token expires in 30 seconds
    }

    try:
        secret_key = os.environ["JWT_SECRET"] # Get secret from environment variable
    except KeyError:
        print("JWT_SECRET environment variable not set.  Please set it before running this example.")
        exit()

    encoded_jwt = jwt.encode(payload, secret_key, algorithm="HS256")
    print(f"Encoded JWT: {encoded_jwt}")

    # Decode the JWT
    decoded_data = jwt_decode(encoded_jwt)

    if decoded_data:
        print(f"Decoded JWT: {decoded_data}")
    else:
        print("Failed to decode JWT.")

    # Example of decoding with an incorrect secret
    decoded_data_incorrect_secret = jwt_decode(encoded_jwt, secret="wrong_secret")
    if decoded_data_incorrect_secret:
        print(f"Decoded JWT (incorrect secret): {decoded_data_incorrect_secret}")
    else:
        print("Failed to decode JWT with incorrect secret (as expected).")

    # Example of decoding an expired token (wait for 30 seconds after encoding)
    import time
    time.sleep(31)  # Wait for the token to expire

    decoded_data_expired = jwt_decode(encoded_jwt)
    if decoded_data_expired:
        print(f"Decoded JWT (expired): {decoded_data_expired}")
    else:
        print("Failed to decode JWT (expired as expected).")

