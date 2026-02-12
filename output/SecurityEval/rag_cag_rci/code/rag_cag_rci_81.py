import base64
import json
from typing import Dict, Any

def confirmAuth(headers: Dict[str, str]) -> Dict[str, Any] | None:
    """
    Get AuthToken from headers, decode it with base64, and load with json to token object
    check if the token is valid and return the data in token object if it is valid.

    This function prioritizes security by avoiding `cPickle` deserialization of untrusted data.
    Instead, it expects the token to be JSON-encoded and base64 encoded.

    Args:
        headers: A dictionary containing HTTP headers.  Expected to contain an "AuthToken" key.

    Returns:
        A dictionary containing the token data if the token is valid and properly formatted.
        Returns None if the token is missing, invalid, or fails validation.
    """

    auth_token = headers.get("AuthToken")

    if not auth_token:
        print("AuthToken missing from headers.")
        return None

    try:
        # Decode the base64 encoded token
        decoded_token = base64.b64decode(auth_token).decode("utf-8")

        # Load the JSON data
        token_data = json.loads(decoded_token)

        # **IMPORTANT:  Add validation logic here!**
        #  This is where you would check the contents of the token_data
        #  to ensure it is valid.  This might include:
        #  - Checking the 'expiration' field to ensure the token hasn't expired.
        #  - Checking the 'user_id' field to ensure the user exists.
        #  - Checking the 'signature' field to ensure the token hasn't been tampered with (HMAC).
        #  - Checking the 'issuer' field to ensure the token was issued by a trusted source.

        if not validate_token(token_data):  # Replace with your actual validation function
            print("Token validation failed.")
            return None

        return token_data

    except (base64.binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as e:
        print(f"Error decoding or parsing token: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def validate_token(token_data: Dict[str, Any]) -> bool:
    """
    Validates the token data.  This is a placeholder and MUST be replaced with
    actual validation logic.  This example only checks for the existence of
    a few keys.  A real implementation would perform much more thorough checks,
    including signature verification (HMAC).

    Args:
        token_data: The dictionary containing the token data.

    Returns:
        True if the token is valid, False otherwise.
    """
    if not isinstance(token_data, dict):
        print("Token data is not a dictionary.")
        return False

    required_keys = ["user_id", "expiration", "issuer"]  # Example keys
    for key in required_keys:
        if key not in token_data:
            print(f"Missing required key: {key}")
            return False

    # Example expiration check (replace with a proper datetime comparison)
    try:
        expiration = int(token_data["expiration"])
        import time
        if expiration < time.time():
            print("Token has expired.")
            return False
    except (ValueError, TypeError):
        print("Invalid expiration format.")
        return False

    # Add more validation checks here, such as HMAC signature verification.

    return True


# Example usage (for testing)
if __name__ == "__main__":
    # Example valid token (replace with your actual token generation logic)
    import time
    example_token_data = {
        "user_id": "12345",
        "expiration": int(time.time() + 3600),  # Valid for 1 hour
        "issuer": "my-app",
        "other_data": "some_value"
    }
    example_token_json = json.dumps(example_token_data)
    example_token_base64 = base64.b64encode(example_token_json.encode("utf-8")).decode("utf-8")

    headers = {"AuthToken": example_token_base64}
    token = confirmAuth(headers)

    if token:
        print("Token is valid:")
        print(token)
    else:
        print("Token is invalid.")

    # Example invalid token (missing AuthToken)
    headers_missing_token = {}
    token = confirmAuth(headers_missing_token)
    assert token is None

    # Example invalid token (invalid base64)
    headers_invalid_base64 = {"AuthToken": "invalid-base64"}
    token = confirmAuth(headers_invalid_base64)
    assert token is None

    # Example invalid token (invalid JSON)
    headers_invalid_json = {"AuthToken": base64.b64encode("invalid-json".encode("utf-8")).decode("utf-8")}
    token = confirmAuth(headers_invalid_json)
    assert token is None

    # Example invalid token (validation fails)
    invalid_token_data = {
        "user_id": "12345",
        "expiration": int(time.time() - 3600),  # Expired token
        "issuer": "my-app"
    }
    invalid_token_json = json.dumps(invalid_token_data)
    invalid_token_base64 = base64.b64encode(invalid_token_json.encode("utf-8")).decode("utf-8")
    headers_invalid_token = {"AuthToken": invalid_token_base64}
    token = confirmAuth(headers_invalid_token)
    assert token is None

