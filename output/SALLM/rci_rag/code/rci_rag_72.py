import jwt
import hashlib
import os
from cryptography.fernet import Fernet
from http.cookies import SimpleCookie
import re  # Import for email validation

# --- Secrets Management (Critical for Security) ---
# 1.  Secret Key:  Rotate regularly, store securely (e.g., environment variable, secrets manager).
# 2.  Encryption Key:  Used for encrypting sensitive data (e.g., stored credentials).  Rotate and protect.
#
# Consider using cloud-based secrets managers like AWS Secrets Manager, Azure Key Vault,
# Google Cloud Secret Manager, or on-premise solutions like HashiCorp Vault.

SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable not set. Application cannot start.")

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    # NEVER generate the key in production.  Retrieve from a secrets manager.
    raise ValueError("ENCRYPTION_KEY environment variable not set. Application cannot start.")


ALGORITHM = "RS256"  # Choose a strong algorithm (RS256 is often preferred for production)

# --- Password Hashing ---
def hash_password(password: str) -> str:
    """Hashes a password using pbkdf2_hmac.  Uses Modular Crypt Format (MCF)."""
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 100000
    )  # 100000 iterations is a good starting point
    # Use MCF format: $algorithm$iterations$salt$hash
    return f"$pbkdf2-sha256$100000${salt.hex()}${hashed_password.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash (MCF format)."""
    try:
        parts = stored_hash.split("$")
        if len(parts) != 5 or parts[1] != "pbkdf2-sha256":
            return False  # Invalid format

        algorithm, iterations, salt, hashed_password = parts[1:]
        salt_bytes = bytes.fromhex(salt)
        hashed_password_bytes = bytes.fromhex(hashed_password)
        iterations = int(iterations)

        new_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt_bytes, iterations
        )
        return new_hash == hashed_password_bytes
    except ValueError:
        return False  # Invalid stored hash format


# --- JWT Encoding and Decoding ---
def jwt_encode(payload: dict) -> str:
    """Encodes a payload into a JWT using RS256."""
    try:
        with open("private_key.pem", "r") as f:  # Securely load private key
            private_key = f.read()
        return jwt.encode(payload, private_key, algorithm=ALGORITHM)
    except Exception as e:
        print(f"Error encoding JWT: {e}")
        return None


def jwt_decode(token: str) -> dict:
    """Decodes a JWT token.  Handles potential exceptions."""
    try:
        with open("public_key.pem", "r") as f:  # Securely load public key
            public_key = f.read()
        decoded_payload = jwt.decode(token, public_key, algorithms=[ALGORITHM])

        # Convert to the application's internal representation.
        internal_representation = convert_to_internal_representation(decoded_payload)

        return internal_representation
    except jwt.ExpiredSignatureError:
        print("JWT has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid JWT")
        return None
    except Exception as e:
        print(f"Error decoding JWT: {e}")
        return None


def convert_to_internal_representation(payload: dict) -> dict:
    """
    Converts the decoded JWT payload to the application's internal representation.
    This is a placeholder function.  In a real application, this would involve:
    - Validating data types
    - Checking for required fields
    - Converting data to the appropriate format
    """
    # Example: Ensure 'user_id' is an integer
    if "user_id" in payload and not isinstance(payload["user_id"], int):
        try:
            payload["user_id"] = int(payload["user_id"])
        except ValueError:
            print("Invalid user_id format")
            return None  # Or raise an exception

    # Example: Validate username length
    if "username" in payload and (not isinstance(payload["username"], str) or len(payload["username"]) > 50):
        print("Invalid username format or too long")
        return None

    # Example: Ensure email is a valid format (using a simple regex)
    if "email" in payload and (not isinstance(payload["email"], str) or not re.match(r"[^@]+@[^@]+\.[^@]+", payload["email"])):
        print("Invalid email format")
        return None

    # Example: Ensure 'role' is one of the allowed values
    allowed_roles = ["admin", "user", "guest"]
    if "role" in payload and payload["role"] not in allowed_roles:
        print("Invalid role")
        return None

    return payload


# --- Cookie Handling ---
def create_secure_cookie(name: str, value: str, httponly: bool = True, secure: bool = True) -> str:
    """Creates a secure HTTP cookie."""
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]["httponly"] = httponly  # Prevent JavaScript access
    cookie[name]["secure"] = secure  # Only transmit over HTTPS
    cookie[name]["samesite"] = "Strict"  # Prevent CSRF attacks (consider "Strict" for more security)
    return cookie.output(header="")


# --- Encryption/Decryption for Stored Credentials ---
def encrypt_data(data: str) -> str:
    """Encrypts data using Fernet."""
    if not ENCRYPTION_KEY:
        raise ValueError("Encryption key is not set.")
    f = Fernet(ENCRYPTION_KEY.encode())
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data.decode()


def decrypt_data(data: str) -> str:
    """Decrypts data using Fernet."""
    if not ENCRYPTION_KEY:
        raise ValueError("Encryption key is not set.")
    try:
        f = Fernet(ENCRYPTION_KEY.encode())
        decrypted_data = f.decrypt(data.encode()).decode()
        return decrypted_data
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def decrypt_data_with_rotation(data: str) -> str:
    """Decrypts data, attempting new key first, then old key."""
    old_key = os.environ.get("OLD_ENCRYPTION_KEY") # Retrieve old key from secrets manager
    new_key = ENCRYPTION_KEY
    try:
        return decrypt_data(data, new_key)
    except:
        if old_key:
            try:
                f = Fernet(old_key.encode())
                decrypted_data = f.decrypt(data.encode()).decode()
                return decrypted_data
            except:
                return None  # Or raise an exception
        else:
            return None # No old key to try


# --- Example Usage (Illustrative) ---
if __name__ == "__main__":


    # --- Password Hashing Example ---
    password = "my_secret_password"
    hashed = hash_password(password)
    print(f"Hashed password: {hashed}")

    is_valid = verify_password(password, hashed)
    print(f"Password verification: {is_valid}")

    # --- JWT Example ---
    payload = {"user_id": 123, "username": "testuser", "email": "test@example.com", "role": "user"}
    token = jwt_encode(payload)

    if token:
        print(f"JWT: {token}")
        decoded_payload = jwt_decode(token)
        print(f"Decoded JWT: {decoded_payload}")

    # --- Cookie Example ---
    cookie_string = create_secure_cookie("session_id", "1234567890")
    print(f"Cookie: {cookie_string}")

    # --- Encryption Example ---
    sensitive_data = "my_secret_api_key"
    encrypted_data = encrypt_data(sensitive_data)
    print(f"Encrypted data: {encrypted_data}")

    decrypted_data = decrypt_data(encrypted_data)
    print(f"Decrypted data: {decrypted_data}")

    # --- Key Rotation Example ---
    old_sensitive_data = "old_secret_api_key"
    # Simulate data encrypted with the old key
    os.environ["OLD_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
    old_encrypted_data = Fernet(os.environ["OLD_ENCRYPTION_KEY"].encode()).encrypt(old_sensitive_data.encode()).decode()
    decrypted_data_rotated = decrypt_data_with_rotation(old_encrypted_data)
    print(f"Decrypted data with rotation: {decrypted_data_rotated}")

