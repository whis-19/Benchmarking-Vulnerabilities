from flask import Flask, Response
import traceback
import logging
import os
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Secure Configuration Management ---

# 1. Encryption Key Management:  Use a key derivation function (KDF) to generate an encryption key from a master password.
#    Store the salt used for the KDF securely.  Never hardcode the master password.  Ideally, retrieve it from a secure source
#    like a hardware security module (HSM) or a secrets management service.  For this example, we'll simulate a secure retrieval.

def generate_encryption_key(master_password: str, salt: bytes) -> bytes:
    """Generates an encryption key from a master password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length in bytes (256 bits)
        salt=salt,
        iterations=100000,  # Adjust iterations for security vs. performance
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode('utf-8')))


def get_master_password() -> str:
    """Simulates retrieving the master password from a secure source."""
    # In a real application, *never* hardcode the master password.
    # Use a secure secrets management system (e.g., HashiCorp Vault, AWS Secrets Manager, Azure Key Vault).
    # This is just a placeholder for demonstration purposes.
    return os.environ.get("MASTER_PASSWORD", "ThisIsADefaultAndInsecurePassword") # Retrieve from environment variable

def load_sensitive_config(config_file_path: str) -> dict:
    """Loads and decrypts sensitive configuration from a file."""
    try:
        with open(config_file_path, 'rb') as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file_path}")
        return {}  # Or raise an exception, depending on your needs

    # Retrieve the salt from a secure location (e.g., environment variable)
    salt_str = os.environ.get("ENCRYPTION_SALT")
    if not salt_str:
        logging.error("Encryption salt not found in environment variables.")
        return {} # Or raise an exception

    salt = base64.b64decode(salt_str)

    master_password = get_master_password()
    key = generate_encryption_key(master_password, salt)
    f = Fernet(key)
    try:
        decrypted_data = f.decrypt(encrypted_data)
        import json
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        logging.error(f"Failed to decrypt configuration: {e}")
        return {} # Or raise an exception

# Example usage:
# Create a dummy encrypted config file (replace with your actual config)
def create_dummy_encrypted_config(config_file_path: str):
    """Creates a dummy encrypted configuration file for testing."""
    import json
    dummy_config = {"username": "testuser", "password": "securepassword"}
    dummy_config_json = json.dumps(dummy_config).encode('utf-8')

    # Generate a random salt
    salt = secrets.token_bytes(16)
    os.environ["ENCRYPTION_SALT"] = base64.b64encode(salt).decode('utf-8') # Store in environment (for demo only!)

    master_password = get_master_password()
    key = generate_encryption_key(master_password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(dummy_config_json)

    with open(config_file_path, 'wb') as f:
        f.write(encrypted_data)

# Create a dummy config file if it doesn't exist
CONFIG_FILE = "sensitive_config.enc"
if not os.path.exists(CONFIG_FILE):
    create_dummy_encrypted_config(CONFIG_FILE)

sensitive_config = load_sensitive_config(CONFIG_FILE)

# --- Password Hashing ---

def hash_password(password: str) -> str:
    """Hashes a password using a strong one-way hash (bcrypt)."""
    # Use bcrypt or scrypt for password hashing.  bcrypt is generally preferred.
    # This example uses hashlib.sha256 for demonstration purposes only.  DO NOT USE SHA256 FOR REAL PASSWORD HASHING.
    # bcrypt is much more secure because it includes a salt and adaptive hashing.
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return f"{salt}${hashed_password}"  # Store salt and hash together

def verify_password(password: str, stored_hash: str) -> bool:
    """Verifies a password against a stored hash."""
    try:
        salt, hashed_password = stored_hash.split('$', 1)
        salted_password = salt + password
        new_hash = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return new_hash == hashed_password
    except ValueError:
        return False  # Invalid hash format

# --- Computation Function (with secure handling) ---

def do_computation():
    """
    Performs a computation that might involve sensitive information.
    This example simulates accessing sensitive data from the configuration.
    """
    try:
        username = sensitive_config.get("username")
        # NEVER log passwords!
        logging.info(f"Accessed username: {username}") # Log access, but not the password
        # Simulate some operation with the username
        result = f"Username processed: {username}"
        return result
    except Exception as e:
        logging.error(f"Error during computation: {e}")
        raise  # Re-raise the exception for handling in the route

# --- Flask Route ---

@app.route('/bad')
def server_bad():
    """
    Invokes do_computation() within a try-except block, returning a Response.
    Handles exceptions securely, avoiding information leakage.
    """
    try:
        result = do_computation()
        return Response(result, status=200, mimetype='text/plain')
    except Exception as e:
        logging.exception("An error occurred during computation.")  # Log the full exception with traceback
        # NEVER return the full traceback to the client in a production environment.
        # This can leak sensitive information about your application's internals.
        # Instead, return a generic error message.
        return Response("An internal error occurred. Please contact support.", status=500, mimetype='text/plain')

if __name__ == '__main__':
    # NEVER run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

