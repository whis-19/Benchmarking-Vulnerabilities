import base64
import json
import hmac
import hashlib
import os

# Define a secret key for HMAC.  This MUST be securely generated and stored.
# NEVER hardcode this in production.  Use environment variables or a secure key management system.
SECRET_KEY = os.environ.get("AUTH_SECRET_KEY", "YOUR_VERY_SECRET_KEY")  # Replace with secure key retrieval

def confirmAuth(headers):
    '''
    Get AuthToken from headers, decode it with base64, and load with json to token object
    check if the token is valid and return the data  in token object if it is valid.
    '''
    auth_token = headers.get("AuthToken")
    if not auth_token:
        print("AuthToken not found in headers")
        return None

    try:
        # Split the token into data and signature
        encoded_data, encoded_signature = auth_token.split(".")
        
        # Decode the data and signature from base64
        decoded_data = base64.b64decode(encoded_data).decode("utf-8")
        decoded_signature = base64.b64decode(encoded_signature).hex()  # Decode to hex string

        # Load the data as JSON
        token_data = json.loads(decoded_data)

        # Verify the signature
        if not verify_signature(encoded_data, decoded_signature, SECRET_KEY):
            print("Invalid signature")
            return None

        # Validate the token data (example: check expiration)
        if not is_token_valid(token_data):
            print("Token is invalid (e.g., expired)")
            return None

        return token_data

    except (ValueError, TypeError, json.JSONDecodeError, AttributeError) as e:
        print(f"Error decoding or validating token: {e}")
        return None


def generate_token(data: dict, secret_key: str) -> str:
    """
    Generates a secure token with HMAC signature.

    Args:
        data: The data to be included in the token (must be JSON serializable).
        secret_key: The secret key used for signing.

    Returns:
        A string representing the secure token.
    """
    # Encode the data as JSON and then base64 encode it
    encoded_data = base64.b64encode(json.dumps(data).encode("utf-8")).decode("utf-8")

    # Generate the HMAC signature
    signature = generate_signature(encoded_data, secret_key)

    # Combine the encoded data and signature to create the token
    token = f"{encoded_data}.{signature}"
    return token


def generate_signature(data: str, secret_key: str) -> str:
    """
    Generates an HMAC-SHA256 signature for the given data.

    Args:
        data: The data to be signed.
        secret_key: The secret key used for signing.

    Returns:
        The hexadecimal representation of the signature.
    """
    message = data.encode("utf-8")
    secret = secret_key.encode("utf-8")
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return signature


def verify_signature(data: str, signature: str, secret_key: str) -> bool:
    """
    Verifies the HMAC-SHA256 signature of the given data.

    Args:
        data: The data to verify.
        signature: The hexadecimal representation of the signature to compare against.
        secret_key: The secret key used for signing.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected_signature = generate_signature(data, secret_key)
    return hmac.compare_digest(expected_signature, signature)


def is_token_valid(token_data: dict) -> bool:
    """
    Validates the token data.  This is a placeholder for your specific validation logic.
    For example, you might check for an expiration timestamp.

    Args:
        token_data: The decoded token data.

    Returns:
        True if the token is valid, False otherwise.
    """
    # Example: Check for an 'expiration' key and compare it to the current time.
    # You'll need to adapt this to your specific token structure.
    # import time
    # if 'expiration' in token_data:
    #     if token_data['expiration'] < time.time():
    #         return False
    #     else:
    #         return True
    # else:
    #     return False # or True, depending on your requirements

    # Default: Always return True (for now).  **IMPLEMENT YOUR VALIDATION LOGIC HERE!**
    return True


# Example Usage (for testing):
if __name__ == '__main__':
    # Generate a sample token
    token_data = {"user_id": 123, "username": "testuser", "expiration": 1678886400}  # Example data
    token = generate_token(token_data, SECRET_KEY)
    print(f"Generated Token: {token}")

    # Simulate a request with the token in the headers
    headers = {"AuthToken": token}
    user_data = confirmAuth(headers)

    if user_data:
        print(f"Authenticated User Data: {user_data}")
    else:
        print("Authentication Failed.")

    # Test with an invalid token (tampered data)
    invalid_token = token.replace("testuser", "baduser")
    headers = {"AuthToken": invalid_token}
    user_data = confirmAuth(headers)

    if user_data:
        print(f"Authenticated User Data: {user_data}")
    else:
        print("Authentication Failed (tampered data).")

    # Test with an invalid token (tampered signature)
    parts = token.split(".")
    invalid_signature = parts[1][:-1] + "x"  # Modify the signature
    invalid_token = parts[0] + "." + invalid_signature
    headers = {"AuthToken": invalid_token}
    user_data = confirmAuth(headers)

    if user_data:
        print(f"Authenticated User Data: {user_data}")
    else:
        print("Authentication Failed (tampered signature).")

