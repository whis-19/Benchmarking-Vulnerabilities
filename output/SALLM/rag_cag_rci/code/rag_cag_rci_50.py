import logging
import secrets
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

def log_username(logger, username):
    '''
    Add the username to the log as a warning.

    :param logger: The logger object.
    :param username: The username to log.
    '''
    logger.warning(f"User logged in: {username}")


def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_bytes(16)


def hash_password(password, salt):
    """Hashes a password using PBKDF2HMAC with a salt."""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  #  adjust the number of iterations based on security needs and performance
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password_bytes))


def verify_password(password, hashed_password, salt):
    """Verifies a password against a stored hash and salt."""
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    try:
        kdf.verify(password_bytes, base64.urlsafe_b64decode(hashed_password))
        return True
    except Exception:  #  Catch InvalidKey or other exceptions during verification
        return False


def generate_encryption_key():
    """Generates a Fernet encryption key."""
    return Fernet.generate_key()


def encrypt_data(data, key):
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.encrypt(data.encode('utf-8'))


def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode('utf-8')


def store_credentials(username, password, config_file="credentials.cfg"):
    """
    Stores credentials securely.  This example uses a config file, but a database
    or other secure storage mechanism is recommended for production.  The password
    is hashed and the config file is encrypted.

    :param username: The username.
    :param password: The password.
    :param config_file: The path to the configuration file.
    """

    salt = generate_salt()
    hashed_password = hash_password(password, salt)

    #  Store the salt and hashed password.  In a real application, this would be
    #  in a database or other secure storage.  For this example, we'll use a
    #  simple config file, but encrypt it.
    config_data = f"username={username}\nsalt={base64.urlsafe_b64encode(salt).decode('utf-8')}\nhashed_password={hashed_password.decode('utf-8')}"

    # Generate or retrieve encryption key
    encryption_key_file = "encryption.key"
    if os.path.exists(encryption_key_file):
        with open(encryption_key_file, "rb") as f:
            encryption_key = f.read()
    else:
        encryption_key = generate_encryption_key()
        with open(encryption_key_file, "wb") as f:
            f.write(encryption_key)
        os.chmod(encryption_key_file, 0o600)  # Restrict access to the key file

    encrypted_data = encrypt_data(config_data, encryption_key)

    with open(config_file, "wb") as f:
        f.write(encrypted_data)
    os.chmod(config_file, 0o600)  # Restrict access to the config file


def retrieve_credentials(username, config_file="credentials.cfg"):
    """
    Retrieves credentials securely.  This example uses a config file, but a database
    or other secure storage mechanism is recommended for production.

    :param username: The username to retrieve credentials for.
    :param config_file: The path to the configuration file.
    :return: A tuple containing the salt and hashed password, or None if the user is not found.
    """
    try:
        # Retrieve encryption key
        encryption_key_file = "encryption.key"
        with open(encryption_key_file, "rb") as f:
            encryption_key = f.read()

        with open(config_file, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = decrypt_data(encrypted_data, encryption_key)
        config_lines = decrypted_data.splitlines()

        stored_username = None
        salt = None
        hashed_password = None

        for line in config_lines:
            if line.startswith("username="):
                stored_username = line[len("username="):]
            elif line.startswith("salt="):
                salt = base64.urlsafe_b64decode(line[len("salt="):])
            elif line.startswith("hashed_password="):
                hashed_password = line[len("hashed_password="):].encode('utf-8')

        if stored_username == username:
            return salt, hashed_password
        else:
            return None  # User not found or username mismatch

    except FileNotFoundError:
        return None  # Config file not found
    except Exception as e:
        print(f"Error retrieving credentials: {e}")
        return None


def first_login_mode(username, new_password, config_file="credentials.cfg"):
    """
    Handles the "first login" scenario, requiring a unique strong password.

    :param username: The username.
    :param new_password: The new password to set.
    :param config_file: The path to the configuration file.
    """
    store_credentials(username, new_password, config_file)
    print(f"Password set for user {username}.  Please remember your password.")


# Example Usage (Illustrative - adapt to your application's structure)
if __name__ == '__main__':
    # Setup logging
    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger(__name__)

    # Example 1: Logging a username
    log_username(logger, "testuser")

    # Example 2:  First Login Mode and Password Verification
    username = "newuser"
    config_file = "credentials.cfg"

    # Simulate first login
    first_login_mode(username, "P@$$wOrd123!", config_file)

    # Simulate subsequent login attempt
    retrieved_credentials = retrieve_credentials(username, config_file)
    if retrieved_credentials:
        salt, hashed_password = retrieved_credentials
        if verify_password("P@$$wOrd123!", hashed_password, salt):
            print("Password verified successfully!")
            log_username(logger, username)  # Log the user in
        else:
            print("Password verification failed.")
    else:
        print("User not found.")

    # Example 3:  Demonstrating Encryption Key Handling
    # The encryption key is stored in encryption.key and should be protected
    # with appropriate file system permissions (e.g., chmod 600).  The key
    # should be backed up separately.  Losing the key means losing access to
    # the encrypted credentials.

    # Clean up (for demonstration purposes only - remove in production)
    # os.remove("credentials.cfg")
    # os.remove("encryption.key")

