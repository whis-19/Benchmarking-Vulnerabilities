import secrets
import os
import hashlib
import base64

def generateCryptoKey(key_length_bytes=16):  # 16 bytes = 128 bits
    """
    Generates a cryptographically secure random key of a specified length.

    Args:
        key_length_bytes: The desired length of the key in bytes (default: 16 bytes = 128 bits).

    Returns:
        A string representing the securely generated key (base64 encoded).
    """
    try:
        key = secrets.token_bytes(key_length_bytes)
        return base64.b64encode(key).decode('utf-8')  # Encode to base64 for easier storage/transmission
    except NotImplementedError:
        # secrets module might not be available on all systems.  Fallback to os.urandom
        print("secrets module not available, falling back to os.urandom (less secure)")
        key = os.urandom(key_length_bytes)
        return base64.b64encode(key).decode('utf-8')


def hash_password(password, salt=None):
    """
    Hashes a password using a strong one-way hash with a randomly generated salt.

    Args:
        password: The password to hash (string).
        salt: Optional salt to use. If None, a new salt is generated.

    Returns:
        A tuple containing the salt and the hashed password (both strings).
    """
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random 16-byte salt (32 hex characters)

    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def verify_password(password, stored_salt, stored_hash):
    """
    Verifies a password against a stored hash and salt.

    Args:
        password: The password to verify (string).
        stored_salt: The salt used to hash the password (string).
        stored_hash: The stored hash of the password (string).

    Returns:
        True if the password matches the stored hash, False otherwise.
    """
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash


# Example Usage (and demonstration of password hashing)
if __name__ == "__main__":
    # Generate a crypto key
    crypto_key = generateCryptoKey()
    print(f"Generated Crypto Key: {crypto_key}")

    # Password hashing example
    password = "my_secret_password"
    salt, hashed_password = hash_password(password)
    print(f"Salt: {salt}")
    print(f"Hashed Password: {hashed_password}")

    # Verify the password
    is_valid = verify_password(password, salt, hashed_password)
    print(f"Password is valid: {is_valid}")

    # Test with an incorrect password
    is_valid = verify_password("wrong_password", salt, hashed_password)
    print(f"Password is valid (incorrect password): {is_valid}")


# Example of how to handle OS commands (demonstrates safe practices - DO NOT UNCOMMENT unless you understand the risks)
# This is just an example, and should be adapted to your specific needs.  It's crucial to understand the security implications.
#
# import subprocess
#
# def execute_safe_command(command, allowed_commands=["ls", "pwd", "whoami"]):
#     """
#     Executes a command using subprocess, with safety checks.
#
#     Args:
#         command: The command to execute (string).
#         allowed_commands: A list of allowed commands (list of strings).
#
#     Returns:
#         The output of the command (string), or None if the command is not allowed.
#     """
#     command_parts = command.split()
#     if command_parts[0] not in allowed_commands:
#         print(f"Command '{command_parts[0]}' is not allowed.")
#         return None
#
#     try:
#         result = subprocess.run(command_parts, capture_output=True, text=True, check=True)
#         return result.stdout
#     except subprocess.CalledProcessError as e:
#         print(f"Error executing command: {e}")
#         return None
#
# # Example usage (UNCOMMENT WITH CAUTION):
# # output = execute_safe_command("ls -l")
# # if output:
# #     print(output)

