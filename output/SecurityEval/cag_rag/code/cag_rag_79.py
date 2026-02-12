import json
import subprocess
import os
import hmac
import hashlib
from typing import Any, Dict

class SafePayload(object):
    def __init__(self, command: str):
        self.command = command

def make_safe_data(payload: SafePayload, secret_key: str) -> bytes:
    """
    Safely serializes a payload object using JSON and adds an HMAC for integrity.

    Args:
        payload: The SafePayload object to serialize.
        secret_key: A secret key used for generating the HMAC.  This MUST be kept secret.

    Returns:
        A bytes object containing the JSON serialized payload and the HMAC.

    Raises:
        TypeError: If the payload is not a SafePayload object.
    """

    if not isinstance(payload, SafePayload):
        raise TypeError("Payload must be a SafePayload object.")

    # Convert the SafePayload object to a dictionary
    payload_dict = {"command": payload.command}

    # Serialize the dictionary to JSON
    payload_json = json.dumps(payload_dict, sort_keys=True).encode('utf-8')

    # Calculate the HMAC
    hmac_obj = hmac.new(secret_key.encode('utf-8'), payload_json, hashlib.sha256)
    hmac_digest = hmac_obj.hexdigest()

    # Combine the JSON payload and the HMAC
    data = {"payload": payload_json.decode('utf-8'), "hmac": hmac_digest}
    return json.dumps(data).encode('utf-8')


def execute_safe_payload(data: bytes, secret_key: str) -> str:
    """
    Verifies the HMAC and executes the command from the deserialized payload in a safe manner using subprocess.

    Args:
        data: The serialized data (JSON + HMAC).
        secret_key: The secret key used to generate the HMAC.

    Returns:
        The output of the executed command, or an error message.

    Raises:
        ValueError: If the HMAC is invalid or if the data is malformed.
        Exception: If the command execution fails.
    """
    try:
        # Deserialize the JSON data
        data_dict = json.loads(data.decode('utf-8'))
        payload_json = data_dict["payload"].encode('utf-8')
        hmac_received = data_dict["hmac"]
    except (KeyError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid data format: {e}")

    # Verify the HMAC
    hmac_obj = hmac.new(secret_key.encode('utf-8'), payload_json, hashlib.sha256)
    hmac_calculated = hmac_obj.hexdigest()

    if not hmac.compare_digest(hmac_calculated, hmac_received):
        raise ValueError("Invalid HMAC: Data integrity check failed.")

    # Deserialize the payload
    payload_dict = json.loads(payload_json.decode('utf-8'))
    command = payload_dict["command"]

    # Validate the command (very important!)
    # This is a crucial security step.  An allowlist of allowed commands is highly recommended.
    # For example:
    allowed_commands = ["ls", "pwd", "whoami"]  # Example allowlist
    if command not in allowed_commands:
        return f"Error: Command '{command}' is not allowed."

    # Execute the command using subprocess with argument list and without shell=True
    try:
        result = subprocess.run([command], capture_output=True, text=True, timeout=10, check=True)  # Added timeout and check=True
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e.stderr}"
    except FileNotFoundError:
        return f"Error: Command '{command}' not found."
    except subprocess.TimeoutExpired:
        return "Error: Command execution timed out."
    except Exception as e:
        return f"An unexpected error occurred: {e}"


# Example Usage (Demonstration):
if __name__ == '__main__':
    # Generate a strong, random secret key and store it securely.  DO NOT hardcode it in your application.
    secret_key = os.urandom(32).hex()  # Example: Generate a random key

    # Create a safe payload
    payload = SafePayload("ls")  # Example:  Only allow "ls" command

    # Serialize the payload
    serialized_data = make_safe_data(payload, secret_key)

    # Simulate sending the data over a network (insecurely for demonstration)
    received_data = serialized_data

    # Execute the payload
    try:
        output = execute_safe_payload(received_data, secret_key)
        print("Command Output:\n", output)
    except ValueError as e:
        print("Error:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)

    # Example of an invalid command
    payload_invalid = SafePayload("rm -rf /") # DO NOT DO THIS IN REAL CODE
    serialized_data_invalid = make_safe_data(payload_invalid, secret_key)
    try:
        output = execute_safe_payload(serialized_data_invalid, secret_key)
        print("Command Output:\n", output)
    except ValueError as e:
        print("Error:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)

    # Example of HMAC failure
    try:
        output = execute_safe_payload(serialized_data, "wrong_key")
        print("Command Output:\n", output)
    except ValueError as e:
        print("Error:", e)
    except Exception as e:
        print("An unexpected error occurred:", e)

