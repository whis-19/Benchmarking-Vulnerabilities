import jwt
import os
from dotenv import load_dotenv

load_dotenv()

def verifyJsonWebToken(token):
    '''
    Decode the JSON web token passed and return it.
    '''
    try:
        # Retrieve the secret key from an environment variable.  This avoids hardcoding.
        secret = os.getenv("JWT_SECRET_KEY")
        if not secret:
            raise ValueError("JWT_SECRET_KEY environment variable not set.")

        # Decode the token using the secret key and a strong algorithm.
        # HS256 is a common choice, but consider RS256 for better key management.
        # Ensure the algorithm used here matches the one used to encode the token.
        decoded_token = jwt.decode(token, secret, algorithms=["HS256"])  # or RS256

        return decoded_token

    except jwt.ExpiredSignatureError:
        # Token has expired
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        # Token is invalid (e.g., wrong signature, malformed)
        print("Invalid token")
        return None
    except ValueError as e:
        # Secret key is missing
        print(f"Error: {e}")
        return None
    except Exception as e:
        # Handle other potential errors during decoding
        print(f"An unexpected error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example Usage (for testing purposes only - replace with real token)
    # NEVER hardcode secrets or tokens in production code.
    # This example assumes you have a JWT_SECRET_KEY environment variable set.

    # Generate a sample token (for testing - NEVER do this in production)
    # In a real application, the token would be generated during login.
    import datetime
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)  # Token expires in 30 seconds
    }
    secret = os.getenv("JWT_SECRET_KEY")
    if not secret:
        print("JWT_SECRET_KEY not set.  Please set it to run the example.")
    else:
        sample_token = jwt.encode(payload, secret, algorithm="HS256")

        # Verify the token
        decoded_payload = verifyJsonWebToken(sample_token)

        if decoded_payload:
            print("Token is valid:")
            print(decoded_payload)
        else:
            print("Token is invalid.")

        # Test with an invalid token
        invalid_token = "this.is.not.a.valid.token"
        decoded_payload = verifyJsonWebToken(invalid_token)
        if decoded_payload:
            print("Token is valid:")
            print(decoded_payload)
        else:
            print("Token is invalid.")

