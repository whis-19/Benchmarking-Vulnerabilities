import os
import stat
import secrets
import logging
import hashlib
import json  # For secure JSON handling
import yaml  # For secure YAML handling
from cryptography.fernet import Fernet # Import for encryption example

# Configure logging (important for auditing and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a maximum configuration size to prevent denial-of-service
MAX_CONFIG_SIZE = 1024 * 10  # 10KB

def write_secure_config(filename="important_config", config_data="important_config"):
    """
    Writes configuration data to a file with restricted permissions.

    Args:
        filename (str): The name of the configuration file.
        config_data (str): The data to write to the file.  This should ideally
                             be encrypted or otherwise secured if it contains
                             sensitive information.  Avoid storing plaintext
                             passwords.
    """

    try:
        # 1. Restrict file permissions:  Only the owner (user running the script)
        #    should have read/write access.  No group or other access.
        #    This is crucial for protecting sensitive configuration data.
        umask = os.umask(0o077)  # Set umask to 077 (owner rwx, group/other ---)

        # 2. Open the file in write mode ('w').  This will overwrite the file
        #    if it already exists.  Consider using 'x' (exclusive creation)
        #    if you want to prevent overwriting.
        with open(filename, "wb") as f: # Open in binary write mode
            # Check file size before writing
            if len(config_data) > MAX_CONFIG_SIZE:
                raise ValueError("Config data exceeds maximum allowed size.")

            # 3. Write the configuration data to the file.
            f.write(config_data) # No decoding needed as encrypted_data is already bytes
            # If writing a string, consider encoding it explicitly (e.g., config_data.encode('utf-8'))

        # 4. Explicitly close the file (using 'with' ensures this happens even if errors occur).
        #    The 'with' statement handles closing the file automatically.

        # 5. Further restrict permissions using chmod (redundant but adds an extra layer).
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only

        logging.info(f"Successfully wrote configuration to {filename} with secure permissions.")

    except OSError as e:
        logging.error(f"Error writing to {filename}: {e}")
    except ValueError as e:
        logging.error(f"Error: {e}")
    finally:
        # Restore the original umask.  This is important to avoid affecting
        # other parts of the system.
        os.umask(umask)


def generate_salt():
    """Generates a random salt for password hashing."""
    return secrets.token_hex(16)  # 16 bytes = 32 hex characters


def hash_password(password, salt):
    """Hashes a password using a salt (example using hashlib)."""
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password


def encrypt_config_data(data, key):
    """Encrypts the configuration data."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return encrypted_data

def store_secure_credentials(filename="credentials.config", username="myuser", password="mypassword"):
    """
    Stores credentials securely (using hashing and salting) and encrypts the entire file.

    Args:
        filename (str): The name of the credentials file.
        username (str): The username.
        password (str): The password.
    """
    try:
        salt = generate_salt()
        hashed_password = hash_password(password, salt)

        # Store the username, salt, and hashed password in a JSON format.
        config_data = json.dumps({"username": username, "salt": salt, "hashed_password": hashed_password})

        # Retrieve the encryption key (from a secure source!)
        key = os.environ.get("CONFIG_ENCRYPTION_KEY")
        if not key:
            logging.error("Encryption key not found!")
            return

        # Ensure the key is a bytes object
        key_bytes = key.encode('utf-8')  # Or another suitable encoding

        # Encrypt the config data
        encrypted_data = encrypt_config_data(config_data, key_bytes)

        # Write the encrypted data to the file
        with open(filename, "wb") as f:  # Open in binary write mode
            f.write(encrypted_data)

        # Restrict file permissions
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

        logging.info(f"Successfully stored secure credentials in {filename}.")

    except Exception as e:
        logging.error(f"Error storing secure credentials: {e}")


def load_config(filename="important_config", config_format="text"):
    """Loads configuration data from a file, handling different formats securely."""
    try:
        with open(filename, "rb") as f: # Open in binary read mode
            config_data = f.read()

        if config_format == "json":
            try:
                config = json.loads(config_data.decode('utf-8')) # Decode before parsing
                return config
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON: {e}")
                return None
        elif config_format == "yaml":
            try:
                config = yaml.safe_load(config_data.decode('utf-8'))  # Use safe_load to prevent insecure deserialization
                return config
            except yaml.YAMLError as e:
                logging.error(f"Error decoding YAML: {e}")
                return None
        else:  # Default to text
            return config_data.decode('utf-8') # Decode before returning

    except FileNotFoundError:
        logging.error(f"Configuration file not found: {filename}")
        return None
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        return None


def example_usage():
    """Example of how to use the functions."""

    # 1.  Write a simple configuration file.
    write_secure_config()

    # 2.  Store credentials securely (hashing and salting).
    store_secure_credentials()

    # 3.  Example of *avoiding* storing plaintext passwords.
    #     Instead of:
    #     write_secure_config("bad_config", "username=myuser\npassword=mypassword")
    #     Use store_secure_credentials() or a similar method.

    # 4. Load configuration data (example with JSON)
    config = load_config("credentials.config", "json")
    if config:
        logging.info(f"Loaded configuration: {config}")

    # 5. Load configuration data (example with YAML - requires pyyaml)
    # You'll need to install pyyaml: pip install pyyaml
    # Create a sample YAML file:
    # with open("config.yaml", "w") as f:
    #     yaml.dump({"setting1": "value1", "setting2": 123}, f)
    # yaml_config = load_config("config.yaml", "yaml")
    # if yaml_config:
    #     logging.info(f"Loaded YAML configuration: {yaml_config}")

    # 6. Key Rotation Example (Conceptual - requires a secure key store)
    # In a real application, this would be a much more complex process.
    # The following is a simplified example for illustrative purposes only.
    #
    # # 1. Retrieve the current key from a secure location (e.g., Vault, KMS)
    # current_key = os.environ.get("CONFIG_ENCRYPTION_KEY")
    # if not current_key:
    #     logging.error("Current encryption key not found!")
    #     return
    #
    # # 2. Generate a new key
    # new_key = Fernet.generate_key().decode() # Only for testing, NEVER store this in code!
    # print("Generated a new key.  DO NOT STORE THIS IN CODE!")
    #
    # # 3. Re-encrypt the configuration data with the new key
    # # (This would involve reading the existing configuration data,
    # # decrypting it with the current key, and then encrypting it
    # # with the new key.)
    #
    # # 4. Store the new key in the secure location
    # # (This would involve updating the key in Vault, KMS, or whatever
    # # secure key store is being used.)
    #
    # # 5. (Optionally) Store the old key for a limited time to allow for
    # # decryption of older data.
    # # (This would require a mechanism for tracking which key was used
    # # to encrypt which data.)
    #
    # logging.info("Key rotation complete (conceptual example).")


if __name__ == "__main__":
    example_usage()

