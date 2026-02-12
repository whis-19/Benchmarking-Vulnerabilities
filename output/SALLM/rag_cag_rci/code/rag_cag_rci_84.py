import jwt
import os
import secrets
import hashlib
from datetime import datetime, timedelta

# --- Security Configuration ---
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))  # Use environment variable for secret key
ALGORITHM = "HS256"  # HMAC SHA-256 - a strong, widely supported algorithm

# --- Helper Functions ---

def generate_salt():
    """Generates a cryptographically secure random salt."""
    return secrets.token_hex(16)

def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password

def verify_password(password, stored_salt, stored_hash):
    """Verifies the password against the stored hash and salt."""
    hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash

def generate_jwt(payload, expiry_minutes=30):
    """
    Generates a JSON Web Token (JWT).

    Args:
        payload (dict): The payload to encode in the JWT.  Should NOT contain sensitive information.
        expiry_minutes (int): The number of minutes until the token expires.

    Returns:
        str: The encoded JWT.
    """
    payload['exp'] = datetime.utcnow() + timedelta(minutes=expiry_minutes)
    try:
        encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Error encoding JWT: {e}")  # Log the error, don't expose it directly to the user
        return None  # Or raise a custom exception for better error handling

def jwt_decode(token):
    """
    Decodes a JSON Web Token (JWT).

    Args:
        token (str): The JWT to decode.

    Returns:
        dict: The decoded payload if the token is valid, None otherwise.
    """
    try:
        decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_payload
    except jwt.ExpiredSignatureError:
        print("Token has expired") # Log the error, don't expose it directly to the user
        return None
    except jwt.InvalidTokenError:
        print("Invalid token") # Log the error, don't expose it directly to the user
        return None
    except Exception as e:
        print(f"Error decoding JWT: {e}") # Log the error, don't expose it directly to the user
        return None

# --- Example Usage (Illustrative - Adapt to your specific needs) ---

if __name__ == '__main__':
    # --- User Registration (Example) ---
    username = "testuser"  # In a real application, get this from user input
    password = "securepassword"  # In a real application, get this from user input

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Store username, salt, and hashed_password in your database.  NEVER store the plain text password.
    print(f"User registered: {username}")

    # --- User Login (Example) ---
    # Retrieve the salt and hashed password from the database based on the username.
    retrieved_salt = salt  # Replace with database lookup
    retrieved_hashed_password = hashed_password  # Replace with database lookup

    # Verify the password
    if verify_password(password, retrieved_salt, retrieved_hashed_password):
        print("Login successful!")

        # Create a JWT
        payload = {
            'user_id': 123,  # Replace with the actual user ID from your database
            'username': username, # Include non-sensitive user information
            'role': 'user' # Include non-sensitive role information
        }
        token = generate_jwt(payload)

        if token:
            print(f"Generated JWT: {token}")

            # --- Decode the JWT ---
            decoded_payload = jwt_decode(token)
            if decoded_payload:
                print(f"Decoded JWT payload: {decoded_payload}")
            else:
                print("Failed to decode JWT.")
        else:
            print("Failed to generate JWT.")
    else:
        print("Login failed: Invalid credentials.")

