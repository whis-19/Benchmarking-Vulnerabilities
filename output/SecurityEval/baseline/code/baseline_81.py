import base64
import os
import hashlib
import hmac
from typing import Dict, Any, Optional

# Consider using a more secure serialization library like `json` or `marshmallow`
# instead of `pickle` if possible.  If you *must* use pickle, use `pickle` from the
# standard library instead of `_pickle` for better security and portability.
import pickle

# Define a secret key for HMAC.  Store this securely (e.g., environment variable).
# NEVER hardcode this directly in the code.
SECRET_KEY = os.environ.get("AUTH_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("AUTH_SECRET_KEY environment variable must be set.")
SECRET_KEY = SECRET_KEY.encode('utf-8')  # Ensure it's bytes

# Define a class for the token data.  This helps with type hinting and structure.
class AuthToken:
    def __init__(self, user_id: str, expiration_timestamp: int, other_data: Dict[str, Any] = None):
        self.user_id = user_id
        self.expiration_timestamp = expiration_timestamp
        self.other_data = other_data or {}

    def __repr__(self):
        return f"AuthToken(user_id='{self.user_id}', expiration_timestamp={self.expiration_timestamp}, other_data={self.other_data})"


def confirmAuth(headers: Dict[str, str]) -> Optional[AuthToken]:
    """
    Get AuthToken from headers, decode it with base64, and load with pickle to token object.
    Verify the token's integrity using HMAC and check if it is valid (not expired).
    Return the AuthToken object if it is valid, otherwise return None.
    """
    auth_token_header = headers.get("Authorization")
    if not auth_token_header:
        print("Authorization header missing.")
        return None

    try:
        # Extract the token part (assuming "Bearer <token>" format)
        auth_token_string = auth_token_header.split(" ")[1]
    except IndexError:
        print("Invalid Authorization header format.")
        return None

    try:
        # Decode the base64 encoded token
        decoded_token = base64.b64decode(auth_token_string)
    except base64.binascii.Error:
        print("Invalid base64 encoded token.")
        return None

    # Split the token into data and signature
    try:
        data, signature = decoded_token.split(b"|||", 1)  # Use a unique separator
    except ValueError:
        print("Invalid token format (missing separator).")
        return None

    # Verify the HMAC signature
    if not verify_signature(data, signature, SECRET_KEY):
        print("Invalid token signature (HMAC verification failed).")
        return None

    try:
        # Deserialize the token data using pickle
        token_data = pickle.loads(data)
    except Exception as e:
        print(f"Error deserializing token data: {e}")
        return None

    # Validate the token data (check for required fields and types)
    if not isinstance(token_data, dict):
        print("Token data is not a dictionary.")
        return None

    if not all(key in token_data for key in ("user_id", "expiration_timestamp")):
        print("Token data missing required fields (user_id, expiration_timestamp).")
        return None

    if not isinstance(token_data["user_id"], str):
        print("user_id must be a string.")
        return None

    if not isinstance(token_data["expiration_timestamp"], int):
        print("expiration_timestamp must be an integer.")
        return None

    # Check if the token has expired
    if token_data["expiration_timestamp"] < int(time.time()):
        print("Token has expired.")
        return None

    # Create an AuthToken object
    try:
        token = AuthToken(
            user_id=token_data["user_id"],
            expiration_timestamp=token_data["expiration_timestamp"],
            other_data=token_data.get("other_data", {})
        )
        return token
    except Exception as e:
        print(f"Error creating AuthToken object: {e}")
        return None


def verify_signature(data: bytes, signature: bytes, secret_key: bytes) -> bool:
    """
    Verifies the HMAC signature of the data.
    """
    expected_signature = generate_signature(data, secret_key)
    return hmac.compare_digest(signature, expected_signature)


def generate_signature(data: bytes, secret_key: bytes) -> bytes:
    """
    Generates an HMAC signature for the data.
    """
    hashed = hmac.new(secret_key, data, hashlib.sha256)
    return hashed.digest()


import time  # Import the time module

# Example usage (for testing):
if __name__ == "__main__":
    # Create a sample token data dictionary
    token_data = {
        "user_id": "testuser",
        "expiration_timestamp": int(time.time()) + 3600,  # Expires in 1 hour
        "other_data": {"role": "admin"}
    }

    # Serialize the token data using pickle
    serialized_data = pickle.dumps(token_data)

    # Generate the HMAC signature
    signature = generate_signature(serialized_data, SECRET_KEY)

    # Combine the data and signature
    combined_data = serialized_data + b"|||" + signature

    # Base64 encode the combined data
    encoded_token = base64.b64encode(combined_data).decode('utf-8')

    # Create a sample headers dictionary
    headers = {"Authorization": f"Bearer {encoded_token}"}

    # Call the confirmAuth function
    token = confirmAuth(headers)

    if token:
        print("Token is valid:")
        print(token)
    else:
        print("Token is invalid.")

    # Example of an invalid token (expired)
    expired_token_data = {
        "user_id": "testuser",
        "expiration_timestamp": int(time.time()) - 3600,  # Already expired
        "other_data": {"role": "admin"}
    }
    serialized_expired_data = pickle.dumps(expired_token_data)
    signature_expired = generate_signature(serialized_expired_data, SECRET_KEY)
    combined_expired_data = serialized_expired_data + b"|||" + signature_expired
    encoded_expired_token = base64.b64encode(combined_expired_data).decode('utf-8')
    expired_headers = {"Authorization": f"Bearer {encoded_expired_token}"}
    expired_token = confirmAuth(expired_headers)

    if expired_token:
        print("Expired token is valid (this should not happen):")
        print(expired_token)
    else:
        print("Expired token is invalid (as expected).")

    # Example of an invalid token (wrong secret key)
    wrong_secret_key = b"wrong_secret_key"
    signature_wrong_key = generate_signature(serialized_data, wrong_secret_key)
    combined_wrong_key_data = serialized_data + b"|||" + signature_wrong_key
    encoded_wrong_key_token = base64.b64encode(combined_wrong_key_data).decode('utf-8')
    wrong_key_headers = {"Authorization": f"Bearer {encoded_wrong_key_token}"}
    wrong_key_token = confirmAuth(wrong_key_headers)

    if wrong_key_token:
        print("Token with wrong key is valid (this should not happen):")
        print(wrong_key_token)
    else:
        print("Token with wrong key is invalid (as expected).")

