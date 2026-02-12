import os
import stat
import json
import hashlib
import base64
from cryptography.fernet import Fernet
import subprocess
import shlex
import logging
import tempfile

# --- Configuration ---
CONFIG_FILE = "important_config"
LOG_FILE = "application.log"
KEY_FILE = "encryption.key"  # Store the encryption key separately

# --- Logging Setup ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def generate_key():
    """Generates a new encryption key and saves it to a file."""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)  # Restrict permissions

def load_key():
    """Loads the encryption key from the key file."""
    try:
        with open(KEY_FILE, 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        logging.error("Encryption key file not found. Generating a new one.")
        generate_key()
        return load_key()  # Recursive call to load the newly generated key

def encrypt_data(data, key):
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data, key):
    """Decrypts data using Fernet decryption."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

def hash_password(password):
    """Hashes a password using SHA-256."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def create_config_file(db_host, db_port, db_name, db_user, db_password):
    """Creates the configuration file with encrypted credentials."""

    key = load_key()

    # Encrypt sensitive data
    encrypted_db_user = encrypt_data(db_user, key)
    hashed_db_password = hash_password(db_password)  # Store password as hash

    config_data = {
        "db_host": db_host,
        "db_port": db_port,
        "db_name": db_name,
        "db_user": encrypted_db_user,
        "db_password": hashed_db_password  # Store the hash, not the plaintext password
    }

    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_data, f, indent=4)

        # Restrict file permissions (owner read/write only)
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"Configuration file '{CONFIG_FILE}' created successfully.")

    except Exception as e:
        logging.error(f"Error creating configuration file: {e}")
        raise

def load_config_file():
    """Loads and decrypts the configuration file."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)

        key = load_key()

        # Decrypt sensitive data
        config_data["db_user"] = decrypt_data(config_data["db_user"], key)

        return config_data

    except FileNotFoundError:
        logging.error("Configuration file not found.")
        return None
    except Exception as e:
        logging.error(f"Error loading configuration file: {e}")
        return None

def execute_external_command(command, sandbox=True):
    """Executes an external command using subprocess in a sandboxed environment.

    Args:
        command: The command to execute as a list of strings.
        sandbox: Whether to execute the command in a temporary directory (sandbox).
    """
    try:
        if sandbox:
            # Create a temporary directory for sandboxing
            with tempfile.TemporaryDirectory() as temp_dir:
                logging.info(f"Executing command in sandbox: {temp_dir}")
                # Execute the command in the temporary directory
                result = subprocess.run(command, capture_output=True, text=True, cwd=temp_dir, check=True)
        else:
            result = subprocess.run(command, capture_output=True, text=True, check=True)

        logging.info(f"Command executed successfully: {command}")
        logging.debug(f"Command output: {result.stdout}")
        logging.debug(f"Command error: {result.stderr}")
        return result.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error code {e.returncode}: {command}")
        logging.error(f"Command output: {e.output}")
        logging.error(f"Command error: {e.stderr}")
        raise
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        raise

def main():
    """Main function to demonstrate the configuration file creation and usage."""

    # Example usage:
    db_host = "localhost"
    db_port = 5432
    db_name = "mydatabase"
    db_user = "myuser"
    db_password = "mysecretpassword"

    try:
        create_config_file(db_host, db_port, db_name, db_user, db_password)

        config = load_config_file()

        if config:
            print("Configuration loaded successfully:")
            print(f"Database Host: {config['db_host']}")
            print(f"Database Port: {config['db_port']}")
            print(f"Database Name: {config['db_name']}")
            print(f"Database User: {config['db_user']}")
            print(f"Database Password Hash: {config['db_password']}") # Show the hash, not the original password

            # Example of executing a safe external command
            # The command is statically defined and arguments are carefully controlled.
            # This example uses 'ls -l' to list files in the current directory.
            # IMPORTANT:  Avoid user-supplied input in the command list.
            safe_command = ["ls", "-l"]
            try:
                output = execute_external_command(safe_command)
                print("Output of safe command:")
                print(output)
            except Exception as e:
                print(f"Error executing safe command: {e}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

