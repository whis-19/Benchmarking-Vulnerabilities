import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional, Dict, Any

# Define constants for security parameters
SALT_LENGTH = 16
HASH_LENGTH = 32
AUTH_TOKEN_EXPIRY_SECONDS = 3600  # Example: 1 hour


class AuthToken:
    """
    Represents an authentication token.  This class should be carefully designed
    to hold only necessary data and avoid storing sensitive information directly.
    """

    def __init__(self, user_id: int, username: str, expiry: int):
        self.user_id = user_id
        self.username = username
        self.expiry = expiry  # Unix timestamp of expiry

    def is_valid(self) -> bool:
        """
        Checks if the token is still valid based on the expiry time.
        """
        import time
        return self.expiry > time.time()

    def to_dict(self) -> Dict[str, Any]:
        """
        Returns a dictionary representation of the token (for signing).
        """
        return {
            "user_id": self.user_id,
            "username": self.username,
            "expiry": self.expiry,
        }


def hash_password(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Hashes a password using PBKDF2HMAC with a randomly generated salt.
    If a salt is provided, it uses that salt instead.
    """
    if salt is None:
        salt = os.urandom(SALT_LENGTH)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000, dklen=HASH_LENGTH
    )
    return hashed_password, salt


def verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
    """
    Verifies a password against a stored hash and salt.
    """
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000, dklen=HASH_LENGTH
    )
    return hmac.compare_digest(hashed_password, stored_hash)


def generate_auth_token(user_id: int, username: str, secret_key: str) -> str:
    """
    Generates a secure authentication token.  Uses HMAC to sign the token data.
    """
    import time

    expiry = int(time.time() + AUTH_TOKEN_EXPIRY_SECONDS)
    token = AuthToken(user_id=user_id, username=username, expiry=expiry)
    token_data = token.to_dict()

    # Serialize the token data (using JSON for security)
    import json

    token_string = json.dumps(token_data, sort_keys=True).encode("utf-8")

    # Create an HMAC signature
    hmac_obj = hmac.new(
        secret_key.encode("utf-8"), token_string, hashlib.sha256
    )  # Use a strong hash
    signature = hmac_obj.hexdigest()

    # Combine the token data and signature
    combined_data = f"{token_string.decode('utf-8')}|{signature}"

    # Base64 encode the combined data
    encoded_token = base64.urlsafe_b64encode(combined_data.encode("utf-8")).decode(
        "utf-8"
    )
    return encoded_token


def confirmAuth(headers: Dict[str, str], secret_key: str) -> Optional[AuthToken]:
    """
    Retrieves the authentication token from the headers, verifies its signature,
    and returns the AuthToken object if valid.  Returns None if invalid.
    """
    auth_header = headers.get("Authorization")
    if not auth_header:
        return None

    try:
        # Extract the token from the header (e.g., "Bearer <token>")
        token = auth_header.split(" ")[1]
        decoded_token = base64.urlsafe_b64decode(token.encode("utf-8")).decode(
            "utf-8"
        )

        # Split the token into data and signature
        token_string, signature = decoded_token.split("|")

        # Verify the signature
        hmac_obj = hmac.new(
            secret_key.encode("utf-8"), token_string.encode("utf-8"), hashlib.sha256
        )
        expected_signature = hmac_obj.hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            print("Invalid signature")  # Log this for security auditing
            return None

        # Deserialize the token data (using JSON)
        import json

        token_data = json.loads(token_string)

        # Create an AuthToken object
        auth_token = AuthToken(
            user_id=token_data["user_id"],
            username=token_data["username"],
            expiry=token_data["expiry"],
        )

        # Check if the token is expired
        if not auth_token.is_valid():
            print("Token expired")  # Log this for security auditing
            return None

        return auth_token

    except Exception as e:
        print(f"Error processing authentication token: {e}")  # Log the error
        return None


# Example Usage (for demonstration purposes)
if __name__ == "__main__":
    # IMPORTANT:  Store this securely (e.g., environment variable, secrets manager)
    SECRET_KEY = secrets.token_hex(32)  # Generate a strong, random key

    # Example user credentials (in a real system, these would be retrieved from a database)
    user_id = 123
    username = "testuser"

    # 1. Password Hashing (when creating a new user or changing a password)
    password = "P@$$wOrd"
    hashed_password, salt = hash_password(password)
    print(f"Hashed password: {hashed_password.hex()}")
    print(f"Salt: {salt.hex()}")

    # 2. Password Verification (during login)
    provided_password = "P@$$wOrd"
    is_valid = verify_password(provided_password, hashed_password, salt)
    print(f"Password verification: {is_valid}")

    # 3. Generate an authentication token
    token = generate_auth_token(user_id, username, SECRET_KEY)
    print(f"Generated token: {token}")

    # 4. Simulate an incoming request with the token in the headers
    headers = {"Authorization": f"Bearer {token}"}

    # 5. Authenticate the request
    auth_token = confirmAuth(headers, SECRET_KEY)

    if auth_token:
        print(f"Authentication successful. User ID: {auth_token.user_id}, Username: {auth_token.username}")
    else:
        print("Authentication failed.")

