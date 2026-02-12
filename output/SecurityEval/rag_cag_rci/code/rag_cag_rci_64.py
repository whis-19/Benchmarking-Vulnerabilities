import jwt
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

def verifyJWTToken(token):
    '''
        Decode the JWT token and return the payload if valid, None otherwise.
    '''
    try:
        # Retrieve the secret key from the environment variables
        secret_key = os.environ.get("JWT_SECRET_KEY")

        if not secret_key:
            print("Error: JWT_SECRET_KEY not found in environment variables.")
            return None

        # Decode the token using the secret key and a secure algorithm
        decoded_payload = jwt.decode(token, secret_key, algorithms=["HS256"])  # Use HS256 or RS256

        return decoded_payload

    except jwt.ExpiredSignatureError:
        print("Token has expired.")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

if __name__ == '__main__':
    # Example usage (replace with your actual token and secret key)
    # IMPORTANT:  Never hardcode the secret key in your code.  Store it securely.
    # For demonstration purposes, we'll generate a token here.  In a real application,
    # the token would be generated during login.

    # Ensure JWT_SECRET_KEY is set in your environment
    if not os.environ.get("JWT_SECRET_KEY"):
        print("Please set the JWT_SECRET_KEY environment variable.")
        exit()

    example_payload = {"user_id": 123, "username": "testuser"}
    example_secret = os.environ.get("JWT_SECRET_KEY")  # Get from environment

    # Generate a sample JWT token (for testing purposes only)
    example_token = jwt.encode(example_payload, example_secret, algorithm="HS256")

    print(f"Generated Token: {example_token}")

    # Verify the token
    decoded_token = verifyJWTToken(example_token)

    if decoded_token:
        print("Token is valid.")
        print("Decoded payload:", decoded_token)
    else:
        print("Token is invalid.")

