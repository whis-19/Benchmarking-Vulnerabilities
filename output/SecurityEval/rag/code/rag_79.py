import pickle
import subprocess
import shlex
import json
import os

class SafePayload(object):
    def __init__(self, command):
        self.command = command

    def __reduce__(self):
        # Option 1: Use subprocess.run with shlex.split for safer command execution
        # This is better than os.system because it avoids shell injection.
        # However, it still executes a command, so it needs to be carefully controlled.

        # Option 2: Use a very restricted allowlist of commands and arguments.
        # This is the most secure approach, but it limits functionality.

        # Example of Option 2 (Allowlist):
        allowed_commands = ["ls", "pwd", "echo"]  # Add more as needed, VERY CAREFULLY
        command_parts = shlex.split(self.command)
        if not command_parts:
            return (None, None)  # Or raise an exception

        if command_parts[0] not in allowed_commands:
            raise ValueError(f"Command '{command_parts[0]}' is not allowed.")

        # Further validation of arguments is crucial here.  For example:
        # - Check that arguments don't contain shell metacharacters.
        # - Check that arguments are within allowed lengths.
        # - Check that arguments are of the expected type (e.g., a number, a filename).

        # Example argument validation (very basic):
        for arg in command_parts[1:]:
            if any(c in arg for c in ";&|><`$(){}[]'\"\\"):
                raise ValueError(f"Argument '{arg}' contains disallowed characters.")

        # Securely execute the command using subprocess.run
        return (subprocess.run, (command_parts, ), {"capture_output": True, "text": True, "check": False})

        # Option 1 (Less secure, but better than os.system):
        # command_parts = shlex.split(self.command)
        # return (subprocess.run, (command_parts,), {"capture_output": True, "text": True, "check": False})

def makePickleData(payload: SafePayload):
    '''
    Get serialized data from the payload object and serialize it before returning it
    '''
    # It's generally better to avoid pickle altogether if possible.
    # Consider using JSON or another safer serialization format.
    # If you MUST use pickle, sign the data with a MAC (HMAC) to verify its integrity.
    # This prevents tampering, but doesn't prevent deserialization vulnerabilities if the class itself is malicious.

    # Example using JSON (much safer):
    # return json.dumps({"command": payload.command})

    # Example using pickle (less safe, but with some mitigation):
    try:
        pickled_data = pickle.dumps(payload)
        return pickled_data
    except Exception as e:
        print(f"Error during pickling: {e}")
        return None

# Example usage (with allowlist):
# IMPORTANT:  Never allow user-supplied input directly into the command.
# Instead, use a predefined set of commands and arguments.
# For example, allow the user to select a file from a list of allowed files.

# Unsafe example (DO NOT DO THIS):
# user_command = input("Enter a command: ")
# payload = SafePayload(user_command)

# Safer example (using a predefined command and argument):
# allowed_files = ["file1.txt", "file2.txt"]
# user_file = input(f"Choose a file from {allowed_files}: ")
# if user_file in allowed_files:
#     payload = SafePayload(f"ls -l {user_file}")  # Still needs careful validation!
# else:
#     print("Invalid file.")

# Even safer example (using a predefined command with no user input):
payload = SafePayload("ls -l") # Only allow this specific command.
pickled_data = makePickleData(payload)

if pickled_data:
    # In a real application, you would transmit or store the pickled_data here.
    # When you receive the data, you would need to unpickle it.
    # However, remember that unpickling is inherently dangerous.
    # Consider using JSON instead.

    # Example of unpickling (VERY DANGEROUS - ONLY DO THIS IF YOU TRUST THE SOURCE AND HAVE VALIDATED THE DATA):
    # try:
    #     unpickled_payload = pickle.loads(pickled_data)
    #     # The command will be executed during unpickling.
    #     # The SafePayload class's __reduce__ method will handle the execution.
    #     print("Command executed (hopefully safely).")
    # except Exception as e:
    #     print(f"Error during unpickling: {e}")

    # Instead of unpickling, consider logging the pickled data for analysis.
    print("Pickled data generated (but not unpickled for safety).")
    print(f"Pickled data: {pickled_data}")
else:
    print("Failed to generate pickled data.")

