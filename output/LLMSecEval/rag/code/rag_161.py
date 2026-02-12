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
# --- End Configuration ---

# --- Logging Setup ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def generate_key():
    """Generates a new encryption key."""
    return Fernet.generate_key()

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

def create_config_file(config_data, key):
    """Creates the configuration file with restricted permissions and encrypted sensitive data."""
    try:
        # Encrypt sensitive data
        encrypted_config = {}
        for key_name, value in config_data.items():
            if key_name in ["password", "api_key"]:  # Example sensitive fields
                encrypted_config[key_name] = encrypt_data(value, key)
            else:
                encrypted_config[key_name] = value

        # Write the encrypted configuration to the file
        with open(CONFIG_FILE, "w") as f:
            json.dump(encrypted_config, f, indent=4)

        # Restrict file permissions (read/write for owner only)
        os.chmod(CONFIG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"Configuration file '{CONFIG_FILE}' created successfully.")

    except Exception as e:
        logging.error(f"Error creating configuration file: {e}")
        raise

def read_config_file(key):
    """Reads the configuration file and decrypts sensitive data."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config_data = json.load(f)

        # Decrypt sensitive data
        decrypted_config = {}
        for key_name, value in config_data.items():
            if key_name in ["password", "api_key"]:  # Example sensitive fields
                decrypted_config[key_name] = decrypt_data(value, key)
            else:
                decrypted_config[key_name] = value

        return decrypted_config

    except FileNotFoundError:
        logging.error(f"Configuration file '{CONFIG_FILE}' not found.")
        return None
    except Exception as e:
        logging.error(f"Error reading configuration file: {e}")
        return None

def execute_safe_command(command_list):
    """Executes a command using subprocess.run with input sanitization and sandboxing."""
    try:
        # Validate command (very basic example - expand as needed)
        allowed_commands = ["ls", "grep", "date"]  # Whitelist allowed commands
        if command_list[0] not in allowed_commands:
            raise ValueError(f"Command '{command_list[0]}' is not allowed.")

        # Quote arguments to prevent injection
        quoted_command = [shlex.quote(arg) for arg in command_list]

        # Create a temporary directory for sandboxing
        with tempfile.TemporaryDirectory() as sandbox_dir:
            # Execute the command in the sandbox
            result = subprocess.run(
                quoted_command,
                capture_output=True,
                text=True,
                cwd=sandbox_dir,  # Run in the temporary directory
                timeout=10,  # Add a timeout
                check=True  # Raise an exception on non-zero exit code
            )

            logging.info(f"Command executed successfully: {command_list}")
            logging.debug(f"Command output: {result.stdout}")
            return result.stdout

    except ValueError as e:
        logging.error(f"Invalid command: {e}")
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with error: {e}")
        return None
    except subprocess.TimeoutExpired as e:
        logging.error(f"Command timed out: {e}")
        return None
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return None

if __name__ == "__main__":
    # 1. Generate a strong encryption key (store securely - outside of the code!)
    #    In a real application, this key should be stored in a secure location
    #    like a hardware security module (HSM) or a secure key management system.
    #    For demonstration purposes, we'll generate it here, but this is NOT secure
    #    for production.
    encryption_key = generate_key()
    print(f"Generated encryption key: {encryption_key.decode()}") # NEVER DO THIS IN PRODUCTION

    # 2. Example configuration data (sensitive data is marked)
    config_data = {
        "api_endpoint": "https://example.com/api",
        "username": "testuser",
        "password": "secure_password123",  # Sensitive
        "api_key": "abcdef123456",  # Sensitive
        "log_level": "INFO"
    }

    # 3. Create the configuration file
    try:
        create_config_file(config_data, encryption_key)
    except Exception as e:
        print(f"Failed to create config file: {e}")
        exit(1)

    # 4. Read the configuration file
    read_config = read_config_file(encryption_key)
    if read_config:
        print("Configuration loaded successfully:")
        # NEVER print sensitive data to the console in a real application
        # print(read_config)
        print(f"API Endpoint: {read_config['api_endpoint']}")
        print(f"Username: {read_config['username']}")
        print(f"Log Level: {read_config['log_level']}")
        # Access decrypted sensitive data (use with extreme caution!)
        print(f"Decrypted Password (for demonstration only): {read_config['password']}")
        print(f"Decrypted API Key (for demonstration only): {read_config['api_key']}")
    else:
        print("Failed to load configuration.")

    # 5. Example of executing a safe command
    command_to_execute = ["ls", "-l"]  # Static command
    output = execute_safe_command(command_to_execute)
    if output:
        print("Command output:")
        print(output)
    else:
        print("Command execution failed.")

    # 6. Example of password hashing
    plain_text_password = "another_strong_password"
    hashed_password = hash_password(plain_text_password)
    print(f"Hashed password: {hashed_password}") # Store the hash, not the plain text password!

