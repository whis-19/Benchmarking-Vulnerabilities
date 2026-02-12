import jwt
import hashlib
import os
from typing import Optional, Dict, Any
from jwt import exceptions as jwt_exceptions

# Recommended secret key length
RECOMMENDED_SECRET_KEY_LENGTH = 32  # 256 bits

def generate_salt() -> bytes:
    """Generates a random salt for password hashing."""
    return os.urandom(16)

def hash_password(password: str, salt: bytes) -> bytes:
    """Hashes a password using PBKDF2-HMAC with a salt."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Convert password to bytes
        salt,
        100000  # Recommended number of iterations
    )

def verify_password(password: str, salt: bytes, hashed_password: bytes) -> bool:
    """Verifies a password against a stored hash and salt."""
    new_hash = hash_password(password, salt)
    return new_hash == hashed_password

def jwt_decode(token: str, secret: str, algorithms: list = ["HS256"]) -> Optional[Dict[str, Any]]:
    """
    Decodes a JSON Web Token and verifies its signature.

    :param token: The JWT to decode.
    :param secret: The secret key used to sign the JWT.  **IMPORTANT: Keep this secret secure!**
    :param algorithms: A list of allowed algorithms (default: ["HS256"]).  Be specific!

    :return: The decoded payload as a dictionary, or None if decoding fails.
    """
    try:
        # Decode the token.  jwt.decode() handles signature verification.
        # It's crucial to specify the algorithm and secret.
        payload = jwt.decode(token, secret, algorithms=algorithms)

        # Double decoding is intentionally avoided.  Decoding twice is almost never what you want
        # and can introduce vulnerabilities.  Instead, focus on validating the *decoded* payload.

        # Validate the decoded payload.  This is where you check for expected fields,
        # data types, and acceptable values.  This is *critical* for security.
        if not isinstance(payload, dict):
            print("Error: Decoded payload is not a dictionary.")
            return None

        # Example validation: Check for a required 'user_id' field.
        if 'user_id' not in payload:
            print("Error: 'user_id' field is missing from the payload.")
            return None

        if not isinstance(payload['user_id'], int):
            print("Error: 'user_id' field is not an integer.")
            return None

        # Add more validation checks as needed based on your application's requirements.
        # Validate data types, ranges, and any other constraints.

        return payload

    except jwt_exceptions.ExpiredSignatureError:
        print("Error: JWT has expired.")
        return None
    except jwt_exceptions.InvalidSignatureError:
        print("Error: Invalid JWT signature.")
        return None
    except jwt_exceptions.DecodeError:
        print("Error: Could not decode JWT.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example Usage (Illustrative - Replace with secure storage and handling)
if __name__ == '__main__':
    # 1. Password Hashing and Verification
    password = "my_secret_password"
    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    # Store salt and hashed_password securely (e.g., in a database).  DO NOT store the plaintext password.

    # Verification
    attempted_password = "my_secret_password"
    if verify_password(attempted_password, salt, hashed_password):
        print("Password verified successfully!")
    else:
        print("Password verification failed.")

    # 2. JWT Encoding and Decoding (Illustrative - Replace with secure key management)
    secret_key = os.urandom(RECOMMENDED_SECRET_KEY_LENGTH).hex()  # Generate a strong, random secret key
    payload = {
        'user_id': 123,
        'username': 'testuser',
        'exp': 1678886400  # Example expiration timestamp (seconds since epoch)
    }

    # Encode the JWT
    encoded_jwt = jwt.encode(payload, secret_key, algorithm="HS256")
    print(f"Encoded JWT: {encoded_jwt}")

    # Decode the JWT
    decoded_payload = jwt_decode(encoded_jwt, secret_key, algorithms=["HS256"])

    if decoded_payload:
        print(f"Decoded Payload: {decoded_payload}")
    else:
        print("JWT decoding failed.")


# Secure Cookie Example (Illustrative - Use a framework for proper handling)
def create_secure_cookie(user_id: int, session_id: str) -> str:
    """Creates a secure HTTP-only cookie.  **Use a web framework for proper cookie handling.**"""
    # Never directly embed user input into the cookie value.
    # Instead, use a unique session ID or token.
    cookie_value = f"session_id={session_id}; user_id={user_id}"  # Example - use session ID in real app

    # Set secure attributes.  These are *essential* for security.
    cookie_string = f"Set-Cookie: {cookie_value}; HttpOnly; Secure; SameSite=Strict"
    return cookie_string

# Example of storing credentials securely (Illustrative - Use a proper secrets management system)
def store_credentials_securely(username: str, password: str, filename: str = "credentials.enc"):
    """
    Encrypts and stores credentials securely.  **Use a proper secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager) in a real application.**
    This example uses Fernet for symmetric encryption.
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import base64

    # Generate a key from a password (DO NOT HARDCODE THE PASSWORD)
    password_provided = "master_password" # This is input in the application
    password = password_provided.encode()  # Convert to type bytes
    salt = os.urandom(16)  # Use a different salt for each key generation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))

    f = Fernet(key)

    # Prepare the data to be encrypted
    data = f"{username}:{password}".encode()

    # Encrypt the data
    encrypted_data = f.encrypt(data)

    # Store the encrypted data and the salt (required for decryption)
    with open(filename, "wb") as f:
        f.write(salt + encrypted_data)

def retrieve_credentials_securely(filename: str = "credentials.enc") -> Optional[tuple[str, str]]:
    """
    Retrieves and decrypts credentials.  **Use a proper secrets management system in a real application.**
    """
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import base64

    try:
        with open(filename, "rb") as f:
            combined_data = f.read()
            salt = combined_data[:16]
            encrypted_data = combined_data[16:]

        # Generate the key from the password (DO NOT HARDCODE THE PASSWORD)
        password_provided = "master_password" # This is input in the application
        password = password_provided.encode()  # Convert to type bytes
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=390000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        f = Fernet(key)

        # Decrypt the data
        decrypted_data = f.decrypt(encrypted_data).decode()

        # Split the data into username and password
        username, password = decrypted_data.split(":", 1)
        return username, password

    except Exception as e:
        print(f"Error retrieving credentials: {e}")
        return None

