import os
import stat
import secrets
import logging
import bcrypt
import re
import json

# Configure logging (important for auditing and debugging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
        #    We use umask to ensure that newly created files have the desired permissions.
        umask = os.umask(0o077)  # Set umask to 077 (owner rwx, group/other ---)

        # 2. Open the file in exclusive creation mode ('x').  This prevents overwriting
        #    existing files, which could lead to data loss.  Using 'with' ensures the file is closed.
        try:
            with open(filename, "x") as f:
                # 3. Write the configuration data to the file.
                f.write(config_data)
        except FileExistsError:
            logging.error(f"File {filename} already exists.  Cannot overwrite.  Consider a different update mechanism.")
            return False  # Indicate failure to write

        # 4. Explicitly close the file (using 'with' ensures this happens even if errors occur).
        #    The 'with' statement handles closing the file automatically.

        # 5. Further restrict permissions using chmod (redundant but adds an extra layer).
        #    The stat module provides constants and functions for working with file status information.
        #    stat.S_IRUSR | stat.S_IWUSR sets the file permissions to allow only the owner (user) to read and write the file.
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)  # Owner read/write only

        logging.info(f"Successfully wrote configuration to {filename} with secure permissions.")
        return True # Indicate success

    except OSError as e:
        logging.error(f"Error writing to {filename}: {e}")
        return False
    finally:
        # Restore the original umask.  This is important to avoid affecting
        # other parts of the system.
        os.umask(umask)


def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    """Checks if a password matches a bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def store_secure_credentials(filename="credentials.json", username="myuser", password="mypassword"):
    """
    Stores credentials securely (using bcrypt).  This is a *much*
    better approach than storing plaintext passwords.  Stores the
    hashed password in a separate file.

    Args:
        filename (str): The name of the credentials file (JSON).
        username (str): The username.
        password (str): The password.
    """
    try:
        # Input Validation
        if not re.match(r"^[a-zA-Z0-9_-]+$", username):
            raise ValueError("Invalid username format.  Only alphanumeric characters, underscores, and hyphens are allowed.")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")

        hashed_password = hash_password(password)

        # Store the username and hashed password in a JSON file.
        credentials = {
            "username": username,
            "hashed_password": hashed_password
        }

        # Write the credentials to the file as JSON.
        if write_secure_config(filename, json.dumps(credentials)):
            logging.info(f"Successfully stored secure credentials in {filename}.")
        else:
            logging.error(f"Failed to write credentials to {filename}.")


    except ValueError as ve:
        logging.error(f"Input validation error: {ve}")
    except OSError as oe:
        logging.error(f"OS error: {oe}")
    except Exception as e:
        logging.error(f"Error storing secure credentials: {e}")


def get_encryption_key():
    """
    Retrieves the encryption key from a secure key management system.
    This is a placeholder function that *must* be implemented with a
    real key management solution (e.g., HashiCorp Vault, AWS KMS).
    DO NOT store the key directly in the code or in environment variables
    in a production environment.
    """
    # Replace this with your actual key retrieval logic.
    # This is just a placeholder to prevent accidental use of insecure methods.
    raise NotImplementedError("Implement key retrieval from a secure key management system.")


def example_usage():
    """Example of how to use the functions."""

    # 1.  Write a simple configuration file.
    write_secure_config()

    # 2.  Store credentials securely (using bcrypt).
    store_secure_credentials()

    # 3.  Example of *avoiding* storing plaintext passwords.
    #     Instead of:
    #     write_secure_config("bad_config", "username=myuser\npassword=mypassword")
    #     Use store_secure_credentials() or a similar method.

    # Example of using environment variables for key management (simple deployment)
    # WARNING: Storing the encryption key in an environment variable is NOT recommended
    # for production environments.  It is vulnerable to various attacks.  Use a
    # dedicated key management system like HashiCorp Vault, AWS KMS, or Azure Key Vault.
    # This example is for demonstration purposes only.
    try:
        encryption_key = get_encryption_key()
        logging.info("Encryption key retrieved from secure source.")
    except NotImplementedError:
        logging.error("No secure key management system configured!")
        encryption_key = None # or handle the error appropriately


if __name__ == "__main__":
    example_usage()

# Additional Security Considerations (Defense in Depth):
#
# * Encryption: Consider using the `cryptography` library for encryption. It's a well-regarded and actively maintained library.
#   Example:
#   from cryptography.fernet import Fernet
#   key = Fernet.generate_key() # Store this securely!
#   cipher = Fernet(key)
#   encrypted_data = cipher.encrypt(config_data.encode())
#
# * Key Management: For simple deployments, you can store the encryption key in an environment variable and retrieve it using `os.environ.get('ENCRYPTION_KEY')`.
#   However, for production environments, consider more robust key management solutions like HashiCorp Vault or AWS KMS.  Remember that environment variables are not a perfect solution.
#
# * Defense in Depth: This code implements multiple layers of security, including file permissions, hashing, and salting. Relying on a single security measure is risky, and multiple layers provide better protection.
#
# * OWASP Alignment: The security recommendations in this code align with best practices from the Open Web Application Security Project (OWASP), a leading authority on web application security.
#
# * Input Validation: If the configuration data comes from external sources, be sure to validate it carefully to prevent injection attacks. For example, if the username is used in a database query, sanitize the input to prevent SQL injection.
#   Example (very basic):
#   username = input("Enter username: ")
#   if not username.isalnum():
#       raise ValueError("Username must be alphanumeric.")
#
# * Sandbox: For extremely sensitive applications, consider running the code in a sandbox environment (e.g., using Docker, chroot, or AppArmor) to limit its access to system resources.
#
# * Regular Audits: Regularly audit the code and the configuration files to ensure that they are secure and that no vulnerabilities have been introduced.
#
# * Principle of Least Privilege: Grant the user running the script only the minimum necessary permissions to access the configuration file and other resources.

