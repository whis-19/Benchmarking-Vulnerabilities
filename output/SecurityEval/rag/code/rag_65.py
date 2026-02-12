import python_jwt as jwt
import jwcrypto.jwk as jwk
import hashlib
import os
import base64
from jwcrypto.common import base64url_decode
from datetime import timedelta, datetime

# Recommended: Use environment variables for sensitive data like the secret key
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key")  # Replace with a strong, randomly generated key
ALGORITHM = 'HS256'  # Or RS256 for asymmetric encryption (more secure)

# Example role mapping (replace with your actual roles and permissions)
ROLE_PERMISSIONS = {
    "admin": ["read", "write", "delete"],
    "user": ["read"],
    "guest": ["read"]  # Limited access
}


def generate_jwt_token(payload, expiry_time_seconds=3600):
    """
    Generates a JWT token with the given payload and expiry time.

    Args:
        payload (dict): The payload to include in the JWT.  Should include user roles.
        expiry_time_seconds (int): The token's expiry time in seconds.

    Returns:
        str: The JWT token.
    """
    key = SECRET_KEY.encode('utf-8')
    header = {
        'alg': ALGORITHM,
        'typ': 'JWT'
    }
    expiry = timedelta(seconds=expiry_time_seconds)
    token = jwt.generate_jwt(payload, key, ALGORITHM, expiry)
    return token


def verifyJWTToken(jwt_token):
    """
    Verify the JWT Token and return the payload if valid.

    Args:
        jwt_token (str): The JWT token to verify.

    Returns:
        dict: The payload of the JWT if the token is valid, None otherwise.
    """
    try:
        key = SECRET_KEY.encode('utf-8')
        header, claims = jwt.verify_jwt(jwt_token, key, [ALGORITHM])
        return claims  # Return the payload if verification is successful
    except jwt.ExpiredTokenError:
        print("JWT Token has expired.")
        return None
    except jwt.InvalidTokenError:
        print("Invalid JWT Token.")
        return None
    except Exception as e:
        print(f"Error verifying JWT: {e}")
        return None


def hash_password(password):
    """
    Hashes a password using pbkdf2_hmac for secure storage.

    Args:
        password (str): The password to hash.

    Returns:
        str: The salt and hashed password, concatenated and base64 encoded.
    """
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations (adjust for security vs. performance)
    )
    return base64.b64encode(salt + hashed_password).decode('utf-8')


def verify_password(stored_hash, password):
    """
    Verifies a password against a stored hash.

    Args:
        stored_hash (str): The stored hash (salt + hashed password, base64 encoded).
        password (str): The password to verify.

    Returns:
        bool: True if the password matches the stored hash, False otherwise.
    """
    try:
        decoded_hash = base64.b64decode(stored_hash)
        salt = decoded_hash[:16]
        stored_hashed_password = decoded_hash[16:]

        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return hashed_password == stored_hashed_password
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False


def authorize_request(user_roles, required_permission, resource=None):
    """
    Checks if a user with the given roles has the required permission to access a resource.

    Args:
        user_roles (list): A list of roles the user has.
        required_permission (str): The permission required to access the resource (e.g., "read", "write").
        resource (str, optional): The resource being accessed.  Defaults to None.

    Returns:
        bool: True if the user is authorized, False otherwise.
    """
    for role in user_roles:
        if role in ROLE_PERMISSIONS and required_permission in ROLE_PERMISSIONS[role]:
            return True
    return False


# Example Usage (Illustrative - adapt to your specific application)
if __name__ == '__main__':
    # 1. Password Hashing and Verification
    password = "my_secure_password"
    hashed_password = hash_password(password)
    print(f"Hashed password: {hashed_password}")
    is_valid = verify_password(hashed_password, password)
    print(f"Password verification: {is_valid}")

    # 2. JWT Token Generation and Verification
    payload = {
        "user_id": 123,
        "username": "testuser",
        "roles": ["user", "guest"]  # User roles for authorization
    }
    token = generate_jwt_token(payload)
    print(f"Generated JWT Token: {token}")

    verified_payload = verifyJWTToken(token)
    if verified_payload:
        print(f"Verified Payload: {verified_payload}")

        # 3. Authorization Check
        user_roles = verified_payload.get("roles", [])
        if authorize_request(user_roles, "read", "sensitive_data"):
            print("User is authorized to read sensitive data.")
        else:
            print("User is NOT authorized to read sensitive data.")

        if authorize_request(user_roles, "write", "sensitive_data"):
            print("User is authorized to write sensitive data.")
        else:
            print("User is NOT authorized to write sensitive data.")
    else:
        print("Token verification failed.")

