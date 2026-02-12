import os
import stat
import json
import logging
import subprocess
import shlex
import base64
import re  # For regular expression validation

# --- Security Configuration ---
CONFIG_FILE = "important_config.json"
LOG_FILE = "application.log"
ALLOWED_COMMANDS = ["ls", "grep", "date"]  # Whitelist of allowed commands

# --- Logging Setup ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Encryption Helper Functions (unchanged) ---
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password: str, salt: bytes) -> bytes:
    """Generates a Fernet encryption key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts data using Fernet encryption."""
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts data using Fernet decryption."""
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

# --- Secure Key Management Functions (REMOVED - Use Environment Variable) ---
def load_key_from_env(env_var="ENCRYPTION_KEY"):
    """Loads the encryption key from an environment variable."""
    key = os.environ.get(env_var)
    if not key:
        logging.error(f"Encryption key not found in environment variable '{env_var}'.")
        print(f"Error: Encryption key not found in environment variable '{env_var}'.")
        return None
    try:
        return base64.urlsafe_b64decode(key.encode())  # Decode if it's base64 encoded
    except Exception as e:
        logging.error(f"Error decoding key: {e}")
        print(f"Error decoding key: {e}")
        return None


def create_config_file(filename: str, encryption_key: bytes):
    """Creates the configuration file with restricted permissions and encrypts sensitive data."""

    # Sample sensitive data (replace with your actual configuration)
    sensitive_data = {
        "api_key": "YOUR_API_KEY",
        "database_url": "YOUR_DATABASE_URL",
        "encrypted_username": encrypt_data("admin", encryption_key).decode(),  # Encrypt username
        "encrypted_password": encrypt_data("P@$$wOrd", encryption_key).decode(),  # Encrypt password
    }

    try:
        with open(filename, "w") as f:
            json.dump(sensitive_data, f, indent=4)

        # Restrict file permissions (read/write for owner only)
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
        logging.info(f"Configuration file '{filename}' created and secured.")

    except Exception as e:
        logging.error(f"Error creating configuration file: {e}")
        print(f"Error creating configuration file: {e}")


def load_config(filename: str, encryption_key: bytes) -> dict:
    """Loads and decrypts the configuration data."""
    try:
        with open(filename, "r") as f:
            config_data = json.load(f)


        # Decrypt the username and password
        config_data["username"] = decrypt_data(config_data["encrypted_username"].encode(), encryption_key)
        config_data["password"] = decrypt_data(config_data["encrypted_password"].encode(), encryption_key)

        # Remove the encrypted versions from the returned config
        del config_data["encrypted_username"]
        del config_data["encrypted_password"]


        logging.info("Configuration loaded and decrypted successfully.")
        return config_data

    except FileNotFoundError:
        logging.error(f"Configuration file '{filename}' not found.")
        print(f"Error: Configuration file '{filename}' not found.")
        return None
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        print(f"Error loading configuration: {e}")
        logging.exception(e) # Log the full stack trace
        return None

def execute_command(command: str, config: dict):
    """Executes a whitelisted command, preventing command injection."""
    try:
        # 1. Whitelist check
        command_parts = shlex.split(command)  # Split into command and arguments
        if command_parts[0] not in ALLOWED_COMMANDS:
            logging.warning(f"Attempted execution of disallowed command: {command_parts[0]}")
            print(f"Error: Command '{command_parts[0]}' is not allowed.")
            return

        # 2. Input Validation (Example: Validate arguments if needed)
        #    This is highly dependent on the specific commands you allow.
        #    For example, if you allow 'grep', you might want to validate
        #    that the search pattern is safe.
        if command_parts[0] == "grep":
            # Example: Sanitize the grep pattern to prevent shell injection
            pattern = command_parts[1]
            # Simple example:  Escape shell metacharacters
            pattern = pattern.replace("'", "'\\''") # Escape single quotes
            command_parts[1] = pattern
            logging.info(f"Sanitized grep pattern to: {pattern}")

            # More robust validation using regular expressions
            if not re.match(r"^[a-zA-Z0-9\s\.\-]+$", pattern):  # Example: Allow only alphanumeric, spaces, dots, and hyphens
                logging.warning(f"Invalid grep pattern: {pattern}")
                print(f"Error: Invalid grep pattern.")
                return


        # 3. Command Construction (Using shlex.join for safety)
        #    shlex.join is safer than string concatenation because it properly
        #    quotes and escapes special characters.
        safe_command = shlex.join(command_parts)

        # 4. Sandboxing (Mandatory for Production Environments)
        #  Implementing a real sandbox is COMPLEX and requires:
        #   - Containerization (Docker): Isolates the application in a container.
        #   - Resource Limits:  Limits CPU, memory, and disk I/O usage.
        #   - Capabilities: Drops unnecessary Linux capabilities.
        #   - Seccomp Profiles: Restricts system calls.
        #   - AppArmor/SELinux: Enforces mandatory access control policies.
        #  A simple boolean flag is INSUFFICIENT for real sandboxing.
        logging.warning("Command execution is NOT sandboxed!  This is a major security risk.")
        print("WARNING: Command execution is NOT sandboxed!  This is a major security risk.")


        # 5. Execute the command using subprocess.run
        result = subprocess.run(safe_command, shell=False, capture_output=True, text=True, check=True, user='nobody', group='nogroup')  # shell=False is crucial

        logging.info(f"Command executed: {safe_command}")
        print("Command Output:\n", result.stdout)
        if result.stderr:
            logging.warning(f"Command STDERR: {result.stderr}")
            print("Command Error (STDERR):\n", result.stderr)

    except subprocess.CalledProcessError as e:
        logging.error(f"Command execution failed: {e}")
        print(f"Error executing command: {e}")
        if e.stderr:
            print("STDERR:\n", e.stderr)
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        print(f"Error executing command: {e}")
        logging.exception(e) # Log the full stack trace


if __name__ == "__main__":

    # --- Key Management ---
    # In a REAL application, use a KMS/HSM.  This is just for demonstration.
    encryption_key = load_key_from_env()
    if not encryption_key:
        print("Failed to load encryption key from environment. Exiting.")
        exit(1)


    create_config_file(CONFIG_FILE, encryption_key)
    config = load_config(CONFIG_FILE, encryption_key)

    if config:
        # Example usage:  Accessing configuration values
        print("API Key:", config.get("api_key"))
        print("Database URL:", config.get("database_url"))
        print("Username (Decrypted):", config.get("username"))
        print("Password (Decrypted):", config.get("password"))

        # Example: Executing a safe command
        execute_command("ls -l", config)
        execute_command("date", config)
        # Attempting to execute a disallowed command:
        execute_command("rm -rf /important_files", config) # This will be blocked

        # Example of grep with sanitized input
        execute_command("grep 'safe string' myfile.txt", config) # Safe
        # The following is still vulnerable if myfile.txt is attacker-controlled
        # execute_command("grep '$(evil_command)' myfile.txt", config) # Still potentially unsafe

        # Log sensitive information (AVOID THIS IN PRODUCTION - ONLY FOR DEMONSTRATION)
        # logging.info(f"Configuration loaded: {config}") # NEVER DO THIS IN REAL CODE
    else:
        print("Failed to load configuration.")

