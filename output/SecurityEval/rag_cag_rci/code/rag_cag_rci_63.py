import jwt
import os
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def verifyJsonWebToken(token):
    '''
    Decode the JSON web token passed and return it.
    '''
    try:
        # Retrieve the secret key from environment variables
        secret = os.getenv("JWT_SECRET")

        if not secret:
            logging.error("JWT_SECRET environment variable not set.")
            return None  # Or raise an exception, depending on your error handling strategy

        # Decode the token using the secret key and specify the algorithm
        decoded_token = jwt.decode(token, secret, algorithms=["HS256"])  # Use HS256 or the algorithm you used to encode

        return decoded_token

    except jwt.ExpiredSignatureError:
        logging.warning("Token has expired.")
        return None  # Or raise an exception

    except jwt.InvalidTokenError:
        logging.error("Invalid token.")
        return None  # Or raise an exception

    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return None  # Or raise an exception


# Example Usage (for demonstration purposes only - replace with your actual token)
if __name__ == '__main__':
    # This is just an example.  NEVER hardcode a JWT.  Get it from a secure source.
    example_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # Replace with a real token
    decoded_payload = verifyJsonWebToken(example_token)

    if decoded_payload:
        print("Decoded Payload:", decoded_payload)
    else:
        print("Token verification failed.")

