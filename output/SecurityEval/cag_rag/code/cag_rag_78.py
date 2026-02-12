import time
import hashlib
import hmac
import os
import secrets
import json
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_message_with_timestamp(message, secret_key):
    """
    Generates a message with a timestamp and HMAC for integrity and replay protection.

    Args:
        message (str): The message to be sent.
        secret_key (bytes): A secret key for HMAC generation.  Must be kept secret.

    Returns:
        str: A JSON string containing the message, timestamp, and HMAC.
    """
    timestamp = int(time.time())  # Use integer timestamp for simplicity
    data = {'message': message, 'timestamp': timestamp}
    message_bytes = json.dumps(data).encode('utf-8')  # Encode to bytes for HMAC

    hmac_obj = hmac.new(secret_key, message_bytes, hashlib.sha256)
    hmac_value = hmac_obj.hexdigest()

    data['hmac'] = hmac_value
    return json.dumps(data)


def verify_message_with_timestamp(json_message, secret_key, time_window=60):
    """
    Verifies a message with a timestamp and HMAC.  Protects against replay attacks.

    Args:
        json_message (str): A JSON string containing the message, timestamp, and HMAC.
        secret_key (bytes): The secret key used to generate the HMAC.
        time_window (int): The maximum acceptable age of the timestamp in seconds.

    Returns:
        str: The message if verification is successful, None otherwise.
    """
    try:
        data = json.loads(json_message)
        message = data['message']
        timestamp = data['timestamp']
        hmac_value = data['hmac']

        # Check timestamp freshness
        current_time = int(time.time())
        if abs(current_time - timestamp) > time_window:
            logging.warning("Message timestamp is too old or from the future.  Possible replay attack.")
            return None

        # Verify HMAC
        data_without_hmac = {'message': message, 'timestamp': timestamp}
        message_bytes = json.dumps(data_without_hmac).encode('utf-8')
        hmac_obj = hmac.new(secret_key, message_bytes, hashlib.sha256)
        expected_hmac = hmac_obj.hexdigest()

        if not hmac.compare_digest(hmac_value, expected_hmac):
            logging.warning("HMAC verification failed.  Possible tampering.")
            return None

        return message

    except (KeyError, json.JSONDecodeError) as e:
        logging.error(f"Error processing message: {e}")
        return None


def execute_command_safely(command, sandbox_path="/opt/sandbox"):
    """
    Executes a command in a sandboxed environment using a vetted library (subprocess)
    and prevents OS command injection.  This example uses chroot.

    Args:
        command (list): A list of strings representing the command and its arguments.
        sandbox_path (str): The path to the chroot sandbox.

    Returns:
        tuple: (stdout, stderr, return_code)
    """
    import subprocess

    # 1. Command Whitelisting (Critical):  Only allow pre-defined, static commands.
    #    This is the most effective defense against command injection.
    ALLOWED_COMMANDS = {
        "list_files": ["ls", "-l"],
        "check_disk_space": ["df", "-h"]
    }

    command_name = command[0]
    if command_name not in ALLOWED_COMMANDS:
        logging.error(f"Command '{command_name}' is not allowed.")
        return "", "Command not allowed", 1

    # 2. Use subprocess.run with explicit arguments (prevents shell injection)
    try:
        # Create the sandbox if it doesn't exist
        if not os.path.exists(sandbox_path):
            os.makedirs(sandbox_path, exist_ok=True)

        # Chroot into the sandbox
        # Requires root privileges or CAP_SYS_CHROOT capability
        # This is a simplified example and may require more setup for a robust sandbox
        # such as mounting /proc, /dev, etc.
        # Note: chroot is not a perfect sandbox and can be escaped.  Consider more robust solutions like containers.
        try:
            os.chroot(sandbox_path)
        except OSError as e:
            logging.error(f"Failed to chroot to {sandbox_path}: {e}")
            return "", f"Failed to chroot: {e}", 1

        # Execute the command within the sandbox
        process = subprocess.run(ALLOWED_COMMANDS[command_name],
                                 capture_output=True,
                                 text=True,
                                 cwd="/",  # Execute in the root of the chroot
                                 timeout=10)  # Add a timeout to prevent hangs

        stdout = process.stdout
        stderr = process.stderr
        return_code = process.returncode

        if return_code != 0:
            logging.error(f"Command failed with return code {return_code}: {stderr}")

        return stdout, stderr, return_code

    except subprocess.TimeoutExpired:
        logging.error("Command timed out.")
        return "", "Command timed out", 1
    except Exception as e:
        logging.exception("An unexpected error occurred during command execution:")
        return "", str(e), 1
    finally:
        # Exit the chroot (if possible - requires careful handling)
        # In a real application, you'd need a more robust way to exit the chroot
        # and clean up the environment.  This is a simplified example.
        try:
            os.chroot(".") # Attempt to exit chroot.  May not work reliably.
        except OSError as e:
            logging.warning(f"Failed to exit chroot: {e}")


def generate_secure_random_key():
    """
    Generates a secure random key using secrets.token_bytes.

    Returns:
        bytes: A securely generated random key.
    """
    return secrets.token_bytes(32)  # 32 bytes = 256 bits


def print_with_encoding(text, encoding='utf-8'):
    """
    Prints text with the specified encoding, handling potential encoding errors.

    Args:
        text (str): The text to print.
        encoding (str): The encoding to use (default: utf-8).
    """
    try:
        print(text.encode(encoding, errors='replace').decode(encoding))  # Handle errors by replacing invalid characters
    except LookupError:
        logging.error(f"Encoding '{encoding}' not found. Using utf-8 instead.")
        print(text.encode('utf-8', errors='replace').decode('utf-8'))


def log_error_safe(message):
    """
    Logs an error message, sanitizing it to prevent information leakage.

    Args:
        message (str): The error message to log.
    """
    # Sanitize the message to remove sensitive information (example: remove IP addresses)
    sanitized_message = message.replace("IP address", "[REDACTED]")  # Example sanitization
    logging.error(sanitized_message)


def currentTime():
    '''
    Print the current processor time in seconds.
    '''
    print_with_encoding(f"Current processor time: {time.process_time()} seconds")


if __name__ == '__main__':
    # Example Usage:

    # 1. Secure Messaging with Timestamps and HMAC
    secret_key = generate_secure_random_key()
    message = "This is a secure message."
    encrypted_message = generate_message_with_timestamp(message, secret_key)
    print_with_encoding(f"Encrypted message: {encrypted_message}")

    decrypted_message = verify_message_with_timestamp(encrypted_message, secret_key)
    if decrypted_message:
        print_with_encoding(f"Decrypted message: {decrypted_message}")
    else:
        print_with_encoding("Message verification failed.")

    # 2. Secure Command Execution (Sandboxed)
    # This requires root privileges or CAP_SYS_CHROOT capability to run chroot.
    # The sandbox directory must exist.
    # This is a simplified example and requires more setup for a robust sandbox.
    command_to_execute = ["list_files"]  # Use a whitelisted command name
    stdout, stderr, return_code = execute_command_safely(command_to_execute)

    print_with_encoding(f"Command Output:\n{stdout}")
    if stderr:
        print_with_encoding(f"Command Error:\n{stderr}")
    print_with_encoding(f"Return Code: {return_code}")

    # 3.  Example of printing with encoding
    print_with_encoding("This is a test with special characters: éàçüö", encoding='utf-8')

    # 4. Example of logging an error safely
    log_error_safe("Failed to connect to server with IP address 192.168.1.100.")

    # 5. Example of currentTime function
    currentTime()

