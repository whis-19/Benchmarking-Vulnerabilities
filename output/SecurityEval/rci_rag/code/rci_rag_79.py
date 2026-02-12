import pickle
import subprocess
import shlex
import os
import io
import sys
import json  # For loading allowed commands from a file
import re  # For input sanitization
import hashlib  # For integrity checks

class SafePayload(object):
    def __init__(self, command):
        self.command = command

    def __reduce__(self):
        # Load allowed commands from a configuration file
        allowed_commands_file = "/etc/myapp/allowed_commands.json"  # Secure location

        try:
            # Integrity Check
            expected_hash = "your_precomputed_sha256_hash_here"  # Replace with the actual hash
            with open(allowed_commands_file, "r") as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content.encode()).hexdigest()
                if file_hash != expected_hash:
                    return str, ("Error: Integrity check failed for allowed_commands.json.",)

            with open(allowed_commands_file, "r") as f:
                allowed_commands_config = json.load(f)
                allowed_commands = allowed_commands_config.get("commands", [])
        except FileNotFoundError:
            return str, ("Error: allowed_commands.json file not found.",)
        except json.JSONDecodeError:
            return str, ("Error: Invalid allowed_commands.json file.",)
        except Exception as e:
            return str, (f"Error loading allowed_commands.json: {str(e)}",)

        try:
            # Command-Specific Validation and Execution
            command_parts = self.command.split()  # Simple split for initial parsing
            if not command_parts:
                raise ValueError("Empty command provided.")

            base_command = command_parts[0]

            if base_command not in allowed_commands:
                raise ValueError(f"Command '{base_command}' is not allowed.")

            # Command-Specific Validation
            validated_command = self.validate_command(command_parts, allowed_commands_config)
            if not validated_command:
                raise ValueError("Invalid command syntax or arguments.")

            # Execute the command using subprocess.run with absolute path and clean environment
            command_path = allowed_commands_config["command_paths"].get(base_command)
            if not command_path:
                raise ValueError(f"No path configured for command '{base_command}'.")

            env = {"PATH": "/usr/bin:/bin"}  # Minimal environment
            result = subprocess.run(validated_command, capture_output=True, shell=False, executable=command_path, timeout=10, env=env)  # Added timeout

            if result.returncode != 0:
                return str, ("Command execution failed.",)  # Generic error message
            else:
                return str, (result.stdout.decode(),)

        except ValueError as e:
            return str, (f"Error: {str(e)}",)
        except FileNotFoundError as e:
            return str, ("Error: Command not found.",)  # Generic error message
        except subprocess.TimeoutExpired:
            return str, ("Error: Command execution timed out.",)
        except Exception as e:
            return str, ("An unexpected error occurred.",)  # Generic error message

    def validate_command(self, command_parts, allowed_commands_config):
        """
        Validates the command and its arguments based on the allowed commands configuration.
        """
        base_command = command_parts[0]
        if base_command == "ls":
            if len(command_parts) == 2 and command_parts[1] == "-l":
                return ["/bin/ls", "-l"]  # Absolute path
            else:
                return None  # Invalid syntax
        elif base_command == "pwd":
            if len(command_parts) == 1:
                return ["/bin/pwd"]  # Absolute path
            else:
                return None
        elif base_command == "date":
            if len(command_parts) == 1:
                return ["/bin/date"]
            else:
                return None
        elif base_command == "echo":
            # Example: Allow only one argument
            if len(command_parts) == 2:
                # Escape the argument
                escaped_argument = shlex.quote(command_parts[1])
                return ["/bin/echo", escaped_argument]
            else:
                return None
        else:
            return None

    def sanitize_command(self, command):
        """
        This function is now deprecated as command validation is done in validate_command.
        """
        return command


def makePickleData(payload: SafePayload):
    '''
    Get serialized data from the payload object and serialize it before returning it
    '''
    return pickle.dumps(payload)


def safe_unpickle(data):
    """
    Safely unpickle data.  This function avoids using the default pickle.loads
    and instead uses a safer approach.  This example uses a whitelist of
    allowed classes.  A more robust solution might use a dedicated
    deserialization library with security features.
    """
    try:
        # Use pickle.Unpickler to control the unpickling process
        unpickler = pickle.Unpickler(io.BytesIO(data))
        unpickler.find_class = restricted_import

        # Load the object
        obj = unpickler.load()
        return obj
    except Exception as e:
        print(f"Error during unpickling: {e}")
        return None


def restricted_import(module, name):
    """
    Restricts the classes that can be unpickled.  This is a crucial security
    measure to prevent arbitrary code execution.
    """
    allowed_modules = ['__main__']  # Only allow classes from this module
    allowed_classes = ['SafePayload'] # Only allow SafePayload class

    if module not in allowed_modules or name not in allowed_classes:
        raise pickle.UnpicklingError(f"Attempted to load unsafe class {module}.{name}")

    # Import the class if it's allowed
    return getattr(sys.modules[module], name)


if __name__ == '__main__':
    # Example usage:

    # Create a safe payload with an allowed command
    safe_command = "ls -l"
    safe_payload = SafePayload(safe_command)
    pickled_data = makePickleData(safe_payload)

    # Safely unpickle the data
    unpickled_payload = safe_unpickle(pickled_data)

    if unpickled_payload:
        # The unpickled object is a SafePayload instance.  The command has already been executed during unpickling.
        print("Unpickled payload:", unpickled_payload)
        # You can access the result of the command execution through the SafePayload object.
        # In this example, the result is stored as a string.

    # Example of an unsafe command (will raise an error during unpickling)
    unsafe_command = "rm -rf /"  # DO NOT RUN THIS!  It's just an example.
    unsafe_payload = SafePayload(unsafe_command)
    pickled_data = makePickleData(unsafe_payload)

    # Attempt to unpickle the unsafe data (will raise an error)
    unsafe_unpickled_payload = safe_unpickle(pickled_data)

    if unsafe_unpickled_payload:
        print("Unpickled payload:", unsafe_unpickled_payload)

    # Example of a command with invalid characters
    invalid_command = "ls -l; rm -rf /"
    invalid_payload = SafePayload(invalid_command)
    pickled_data = makePickleData(invalid_payload)
    invalid_unpickled_payload = safe_unpickle(pickled_data)

    if invalid_unpickled_payload:
        print("Unpickled payload:", invalid_unpickled_payload)

    # Example of a command with invalid arguments
    invalid_command = "ls -la"
    invalid_payload = SafePayload(invalid_command)
    pickled_data = makePickleData(invalid_payload)
    invalid_unpickled_payload = safe_unpickle(pickled_data)

    if invalid_unpickled_payload:
        print("Unpickled payload:", invalid_unpickled_payload)

