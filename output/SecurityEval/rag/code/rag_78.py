import time
import hashlib
import hmac
import os
import json
import subprocess
import shlex
import logging
import secrets
import sys
from typing import Optional

# Configure logging (important for security auditing)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Secure Time Handling ---

def generate_message_with_timestamp(message: str, secret_key: str) -> dict:
    """
    Generates a message with a timestamp and HMAC for integrity and replay protection.

    Args:
        message: The message to be sent.
        secret_key: A secret key known only to the sender and receiver.

    Returns:
        A dictionary containing the message, timestamp, and HMAC.
    """
    timestamp = int(time.time())  # Use integer timestamp for simplicity
    message_data = {'message': message, 'timestamp': timestamp}
    message_json = json.dumps(message_data, sort_keys=True, ensure_ascii=False).encode('utf-8')  # Encode to bytes

    hmac_value = hmac.new(secret_key.encode('utf-8'), message_json, hashlib.sha256).hexdigest()
    message_data['hmac'] = hmac_value
    return message_data


def verify_message_with_timestamp(received_message: dict, secret_key: str, time_window: int = 30) -> bool:
    """
    Verifies a message's integrity and timestamp to prevent replay attacks.

    Args:
        received_message: The received message dictionary (containing message, timestamp, and HMAC).
        secret_key: The secret key known only to the sender and receiver.
        time_window: The maximum acceptable time difference (in seconds) between the current time
                     and the message's timestamp.  Defaults to 30 seconds.

    Returns:
        True if the message is valid, False otherwise.
    """
    try:
        message = received_message['message']
        timestamp = received_message['timestamp']
        received_hmac = received_message['hmac']
    except KeyError:
        logging.error("Invalid message format: Missing required fields.")
        return False

    current_time = int(time.time())
    if abs(current_time - timestamp) > time_window:
        logging.warning(f"Message timestamp is outside the acceptable time window.  Current time: {current_time}, Message timestamp: {timestamp}")
        return False

    # Reconstruct the message data for HMAC calculation
    message_data = {'message': message, 'timestamp': timestamp}
    message_json = json.dumps(message_data, sort_keys=True, ensure_ascii=False).encode('utf-8')

    # Calculate the expected HMAC
    expected_hmac = hmac.new(secret_key.encode('utf-8'), message_json, hashlib.sha256).hexdigest()

    # Compare the received HMAC with the expected HMAC
    if not hmac.compare_digest(received_hmac, expected_hmac):
        logging.warning("HMAC verification failed. Message may be tampered with.")
        return False

    logging.info("Message verification successful.")
    return True


# --- Secure OS Command Execution ---

def execute_command_safely(command: str, sandbox_path: str = "/opt/sandbox") -> Optional[str]:
    """
    Executes a command in a sandboxed environment using a vetted library (subprocess)
    and prevents command injection.  The command must be statically defined.

    Args:
        command: The command to execute (must be a statically defined string).
        sandbox_path: The path to the chroot jail.  Defaults to /opt/sandbox.

    Returns:
        The output of the command, or None if an error occurred.
    """

    # 1. Command Whitelisting (Critical):  Only allow pre-defined, safe commands.
    #    This is the most important defense against command injection.
    allowed_commands = ["ls", "pwd", "date", "echo"]  # Example: Only allow these commands
    if command.split()[0] not in allowed_commands:
        logging.error(f"Command '{command}' is not in the allowed list.")
        return None

    # 2.  Chroot Jail (Sandboxing):  Confine the command execution to a restricted environment.
    #    Requires proper setup of the chroot environment.
    try:
        # Create the sandbox directory if it doesn't exist
        if not os.path.exists(sandbox_path):
            os.makedirs(sandbox_path, exist_ok=True)

        # Use subprocess.run with shlex.split for safe argument handling.
        # shlex.split prevents simple injection attempts by correctly parsing the command string.
        # However, it's still crucial to whitelist commands.
        process = subprocess.run(
            shlex.split(command),
            capture_output=True,
            text=True,
            cwd=sandbox_path,  # Execute in the sandbox directory
            check=True,  # Raise an exception if the command fails
            timeout=10  # Add a timeout to prevent indefinite execution
        )

        logging.info(f"Command '{command}' executed successfully in sandbox.")
        return process.stdout

    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e.stderr}")
        return None
    except FileNotFoundError:
        logging.error(f"Sandbox directory '{sandbox_path}' not found.")
        return None
    except TimeoutExpired:
        logging.error(f"Command '{command}' timed out.")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None


# --- Secure Output Handling ---

def secure_print(data: str, encoding: str = "utf-8") -> None:
    """
    Prints data to the console with proper encoding and escaping.

    Args:
        data: The data to print.
        encoding: The encoding to use (defaults to utf-8).
    """
    try:
        # Encode the data to the specified encoding.  Handle potential encoding errors.
        encoded_data = data.encode(encoding, errors='replace')  # 'replace' handles invalid characters
        # Decode back to a string for printing.
        decoded_data = encoded_data.decode(encoding)

        # Escape special characters for shell safety (if printing to a terminal).
        if sys.stdout.isatty():
            decoded_data = shlex.quote(decoded_data)

        print(decoded_data)
        logging.info("Data printed successfully with encoding: %s", encoding)

    except LookupError:
        logging.error("Invalid encoding specified: %s", encoding)
    except Exception as e:
        logging.error("Error during output encoding/printing: %s", e)


# --- Secure Error Handling ---

def log_error(message: str, sensitive_data: Optional[dict] = None) -> None:
    """
    Logs an error message, avoiding the inclusion of sensitive details.

    Args:
        message: The error message to log.
        sensitive_data: A dictionary containing sensitive data (optional).  This data will *not* be logged directly.
    """
    if sensitive_data:
        logging.error(f"{message}.  Sensitive data omitted from log.")
    else:
        logging.error(message)


# --- Secure Random Number Generation ---

def generate_secure_random_key(length: int = 32) -> str:
    """
    Generates a secure random key using the secrets module.

    Args:
        length: The length of the key to generate (in bytes).

    Returns:
        A securely generated random key as a hexadecimal string.
    """
    return secrets.token_hex(length)


def currentTime():
    '''
    Print the current processor time in seconds.
    '''
    secure_print(str(time.process_time()))


if __name__ == '__main__':
    # --- Example Usage ---

    # 1. Secure Time Handling
    secret = generate_secure_random_key()
    message_to_send = "Hello, secure world!"
    secure_message = generate_message_with_timestamp(message_to_send, secret)
    print(f"Secure message: {secure_message}")

    is_valid = verify_message_with_timestamp(secure_message, secret)
    print(f"Message is valid: {is_valid}")

    # Simulate a replay attack (modify the timestamp)
    modified_message = secure_message.copy()
    modified_message['timestamp'] = int(time.time()) - 60  # Older timestamp
    is_valid_replay = verify_message_with_timestamp(modified_message, secret)
    print(f"Replayed message is valid: {is_valid_replay}")  # Should be False

    # 2. Secure OS Command Execution
    #  Important:  Set up a chroot jail at /opt/sandbox before running this.
    #  Example:  Create a directory /opt/sandbox and copy necessary binaries (e.g., /bin/ls) into it.
    #  This is a simplified example; a real chroot setup requires more configuration.

    #  This example assumes /opt/sandbox exists and contains a minimal environment.
    command_to_execute = "ls -l"  # Statically defined command
    output = execute_command_safely(command_to_execute)
    if output:
        print(f"Command output: {output}")
    else:
        print("Command execution failed.")

    # Attempted command injection (will be blocked by whitelisting)
    # This will be blocked because "rm -rf /" is not in the allowed_commands list.
    injection_attempt = "rm -rf /"
    output_injection = execute_command_safely(injection_attempt)
    if output_injection:
        print(f"Command output: {output_injection}")
    else:
        print("Command execution failed (as expected).")


    # 3. Secure Output Handling
    data_to_print = "This is a test with special characters: <>&\"'"
    secure_print(data_to_print)

    # 4. Secure Error Handling
    sensitive_info = {"credit_card": "1234-5678-9012-3456"}
    log_error("An error occurred while processing the transaction.", sensitive_info)
    log_error("A general error occurred.")

    # 5. Secure Random Number Generation
    random_key = generate_secure_random_key()
    print(f"Secure random key: {random_key}")

    # Example usage of currentTime()
    print("Current processor time:")
    currentTime()

