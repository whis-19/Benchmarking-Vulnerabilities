import os
import subprocess
import logging
import json
import shlex
import re  # For input validation
import secrets
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidTag

# --- Configuration ---
CONFIG_FILE = "config.json"
KEY_FILE = "encryption.key"
LOG_FILE = "app.log"

# --- Logging Setup ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Key Derivation and Encryption ---

def generate_salt() -> bytes:
    """Generates a random salt for key derivation."""
    return secrets.token_bytes(16)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for Fernet
        salt=salt,
        iterations=390000,  # Recommended minimum by NIST
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_key_from_password(master_password: str) -> bytes:
    """Generates a Fernet key from a master password, storing the salt."""
    salt = generate_salt()
    key = derive_key(master_password, salt)
    # Store the salt alongside the key (consider a more secure storage for production)
    with open("salt.txt", "wb") as f:  # Insecure: Replace with secure storage
        f.write(base64.b64encode(salt))
    return base64.urlsafe_b64encode(key)

def load_key() -> Fernet:
    """Loads the encryption key from a file or generates a new one."""
    try:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
        return Fernet(key)
    except FileNotFoundError:
        logging.error("Encryption key not found.  Application cannot function securely.")
        raise  # Re-raise the exception to halt execution.  Consider a default value only for testing.
    except Exception as e:
        logging.error(f"Error loading encryption key: {e}")
        raise  # Re-raise to halt execution.

def encrypt_data(data: str, fernet: Fernet) -> bytes:
    """Encrypts data using Fernet."""
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, fernet: Fernet) -> str:
    """Decrypts data using Fernet."""
    try:
        return fernet.decrypt(encrypted_data).decode()
    except InvalidTag:
        logging.error("Decryption failed: Invalid tag (likely incorrect key).")
        return None  # Or raise an exception
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None # Or raise an exception

# --- Configuration Loading and Saving ---

def load_config(fernet: Fernet) -> dict:
    """Loads the configuration from a file, decrypting sensitive values."""
    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
            for key, value in config.items():
                if isinstance(value, str) and value.startswith("ENC["):
                    encrypted_value = base64.b64decode(value[4:-1])
                    decrypted_value = decrypt_data(encrypted_value, fernet)
                    if decrypted_value is not None:
                        config[key] = decrypted_value
                    else:
                        logging.warning(f"Failed to decrypt value for key: {key}. Using default or raising exception is recommended.")
                        # Consider: raise ValueError(f"Could not decrypt {key}") or use a default value
    except FileNotFoundError:
        logging.error("Configuration file not found. Using default configuration or exiting is recommended.")
        # Consider: return a default config or raise FileNotFoundError
        return {} # Returning an empty dictionary as a placeholder.
    except json.JSONDecodeError:
        logging.error("Invalid JSON in configuration file.  Exiting.")
        raise # Re-raise to halt execution.
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        raise # Re-raise to halt execution.
    return config

def save_config(config: dict, fernet: Fernet):
    """Saves the configuration to a file, encrypting sensitive values."""
    config_copy = config.copy()  # Avoid modifying the original config
    for key, value in config_copy.items():
        if isinstance(value, str) and key not in ["allowed_commands"]: # Example: Don't encrypt allowed_commands
            encrypted_value = encrypt_data(value, fernet)
            config_copy[key] = "ENC[" + base64.b64encode(encrypted_value).decode() + "]"
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_copy, f, indent=4)
        os.chmod(CONFIG_FILE, 0o600)  # Restrict file permissions (read/write for owner only)
    except Exception as e:
        logging.error(f"Error saving configuration: {e}")

# --- Command Execution ---

def execute_command(command: str, *args: str) -> str:
    """Executes a command, ensuring it's in the allowed list and sanitizing inputs."""
    config = load_config(load_key())
    allowed_commands = config.get("allowed_commands", ["ls", "grep", "head"])  # Default allowed commands

    if command not in allowed_commands:
        logging.warning(f"Attempted to execute disallowed command: {command}")
        return "Error: Command not allowed."

    # Input Validation Example: Validate 'grep' argument
    if command == "grep":
        if len(args) > 0:
            # Example: Validate that the first argument is a safe string
            if not re.match(r"^[a-zA-Z0-9_\-]+$", args[0]):  # Example regex
                logging.warning(f"Invalid grep argument: {args[0]}")
                return "Error: Invalid search term."

    # Input Validation Example: Validate integer argument for 'head'
    if command == "head":
        if len(args) > 0:
            try:
                num_lines = int(args[0])
                if num_lines <= 0:
                    logging.warning(f"Invalid head argument: Number of lines must be positive.")
                    return "Error: Number of lines must be positive."
            except ValueError:
                logging.warning(f"Invalid head argument: Not an integer.")
                return "Error: Argument must be an integer."

    # Sanitize arguments using shlex.quote (still not perfect, but better than nothing)
    sanitized_args = [shlex.quote(arg) for arg in args]

    try:
        full_command = [command] + sanitized_args
        logging.info(f"Executing command: {full_command}")
        result = subprocess.run(full_command, capture_output=True, text=True, check=True, timeout=10) # Added timeout
        logging.info(f"Command '{command}' executed successfully.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed: {e}")
        return f"Error: {e.stderr}"
    except subprocess.TimeoutExpired:
        logging.error(f"Command '{command}' timed out.")
        return "Error: Command timed out."
    except Exception as e:
        logging.error(f"Error executing command: {e}")
        return f"Error: {e}"

# --- Main Application Logic ---

def main():
    """Main application function."""
    try:
        # 1. Key Management (Improved)
        # Prompt for master password (replace with secure input)
        master_password = input("Enter master password: ")
        key = generate_key_from_password(master_password)

        # Save the key to a file (INSECURE - FOR DEMO ONLY)
        with open(KEY_FILE, "wb") as f:
            f.write(key)

        fernet = load_key()

        # 2. Configuration Loading
        config = load_config(fernet)
        print("Loaded configuration:", config)

        # Example: Add a new configuration value (encrypted)
        config["new_secret"] = "This is a very important secret!"
        save_config(config, fernet)

        # 3. Command Execution
        command = input("Enter command to execute: ")
        args_input = input("Enter arguments (space-separated): ")
        args = args_input.split()
        output = execute_command(command, *args)
        print("Command output:", output)

    except Exception as e:
        logging.error(f"Application error: {e}")
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()

# --- Important Considerations and Next Steps ---

# 1. Master Password Management:
#    - NEVER store the master password directly.
#    - Use a secure password storage mechanism (e.g., a password manager).
#    - Consider using hardware security modules (HSMs) for key storage in production.

# 2. Key Rotation:
#    - Implement a key rotation strategy to periodically generate new encryption keys.
#    - This limits the impact of a potential key compromise.

# 3. Input Validation:
#    - Implement robust input validation for ALL user-provided input.
#    - Use regular expressions, whitelists, and other techniques to ensure that input conforms to expected formats.
#    - Sanitize input to prevent command injection, SQL injection, and other vulnerabilities.

# 4. Secrets Management:
#    - Use a dedicated secrets management solution (e.g., HashiCorp Vault, AWS Secrets Manager) to store and manage sensitive data.
#    - Avoid storing secrets directly in configuration files or code.

# 5. Sandboxing:
#    - Isolate the application in a sandbox to limit its access to system resources.
#    - Options include:
#        - **Docker:** Easy to set up and provides good isolation, but adds overhead.  Good for containerizing the entire application.
#        - **AppArmor/SELinux:** More lightweight, but require more configuration and a deeper understanding of the operating system.  Useful for restricting the application's access to specific files and directories.  Requires more configuration and OS knowledge. Can be difficult to debug.
#        - **chroot:** A simpler form of sandboxing, but less secure than Docker or AppArmor/SELinux.  Limited isolation capabilities.  Can be bypassed with sufficient privileges.

# 6. Logging:
#    - Ensure that logging is comprehensive but does not expose sensitive data.
#    - Sanitize log messages to remove any potentially sensitive information.

# 7. Error Handling:
#    - Implement robust error handling to prevent the application from crashing or exposing sensitive information in error messages.
#    - Log errors appropriately.

# 8. Least Privilege:
#    - Run the application with the minimum necessary privileges.
#    - Avoid running the application as root.

# 9. Regular Security Audits:
#    - Conduct regular security audits to identify and address potential vulnerabilities.
#    - Use static analysis tools and penetration testing to assess the security of the application.

# 10. Dependencies:
#     - Keep all dependencies up to date to patch security vulnerabilities.
#     - Use a dependency management tool to track and manage dependencies.

# 11. Secure Key Storage:
#     - **NEVER** store the encryption key in a file directly, especially not alongside the salt.
#     - Use a secure key storage mechanism such as:
#         - **Hardware Security Module (HSM):** Provides the highest level of security for key storage.
#         - **Operating System Key Store (e.g., Keychain on macOS, Credential Manager on Windows):**  Provides a secure way to store keys on the local machine.
#         - **Dedicated Secrets Management System (e.g., HashiCorp Vault):**  Provides a centralized and secure way to store and manage secrets.

# --- Resources ---
# * OWASP Input Validation Cheat Sheet: https://owasp.org/www-project-cheat-sheets/cheatsheets/Input_Validation_Cheat_Sheet.html
# * NIST Password Guidelines: https://pages.nist.gov/800-63-3/sp800-63b.html
# * Docker Documentation: https://docs.docker.com/
# * AppArmor Documentation: https://gitlab.com/apparmor/apparmor/-/wikis/home
# * SELinux Documentation: https://www.selinuxproject.org/
# * HashiCorp Vault Documentation: https://www.vaultproject.io/
# * Python `secrets` module documentation: https://docs.python.org/3/library/secrets.html

