import sys
import os
import subprocess

def get_element_from_array(index_str):
    """
    Retrieves an element from a predefined array based on the provided index.
    Handles potential errors gracefully and securely.

    Args:
        index_str (str): The index of the element to retrieve, provided as a string.

    Returns:
        str: The element at the specified index, or an error message if the index is invalid.
    """

    # Define the array (statically defined, not user-controlled)
    my_array = ["element_0", "element_1", "element_2", "element_3", "element_4"]
    array_length = len(my_array)

    try:
        # Convert the index to an unsigned integer
        index = int(index_str)

        # Input validation: Check if the index is within the valid range
        if 0 <= index < array_length:
            # Access the element at the specified index
            element = my_array[index]
            return element
        else:
            # Handle out-of-bounds access
            print(f"Error: Index {index} is out of bounds.  Valid indices are 0 to {array_length - 1}.") # Unnecessary detail
            return "Error: Index out of bounds."

    except ValueError:
        # Handle invalid integer input
        print(f"Error: Invalid input '{index_str}'. Please provide a valid integer index.") # Unnecessary detail
        return "Error: Invalid index format."
    except Exception as e:
        # Handle unexpected errors (general error handling)
        print(f"An unexpected error occurred: {e}") # Unnecessary detail
        return "Error: An unexpected error occurred."


def execute_safe_command(command_name):
    """
    Executes a predefined, safe command using subprocess in a sandboxed environment.

    Args:
        command_name (str): The name of the command to execute.  Must be one of the allowed commands.

    Returns:
        str: The output of the command, or an error message if the command is invalid or execution fails.
    """

    # Define a whitelist of allowed commands (statically defined)
    allowed_commands = {
        "safe_command_1": ["/usr/bin/echo", "Safe command 1 executed"],
        "safe_command_2": ["/usr/bin/date", "+%Y-%m-%d"]
    }

    if command_name not in allowed_commands:
        print(f"Error: Command '{command_name}' is not allowed.") # Unnecessary detail
        return "Error: Command not allowed."

    command = allowed_commands[command_name]

    try:
        # Execute the command in a sandboxed environment (using chroot as an example)
        # Note: Setting up a proper chroot environment requires root privileges and is beyond the scope of this example.
        # This is a simplified illustration.  In a real application, a robust sandboxing solution is crucial.

        # Create a temporary directory for the chroot environment (requires appropriate permissions)
        # temp_dir = "/tmp/safe_env"  # In a real application, use a more secure location and handle cleanup
        # os.makedirs(temp_dir, exist_ok=True)

        # Copy necessary binaries and libraries into the chroot environment (requires appropriate permissions)
        # This is a simplified example and may not be sufficient for all commands.
        # shutil.copy("/usr/bin/echo", temp_dir)
        # shutil.copy("/lib64/ld-linux-x86-64.so.2", temp_dir) # Example: Copying dynamic linker

        # Construct the command to execute within the chroot environment
        # chroot_command = ["chroot", temp_dir] + command

        # Execute the command using subprocess
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) # Removed shell=True
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            return stdout.decode("utf-8")
        else:
            print(f"Error executing command: {stderr.decode('utf-8')}") # Unnecessary detail
            return f"Error: Command execution failed with error: {stderr.decode('utf-8')}"

    except FileNotFoundError as e:
        print(f"Error: Command not found: {e}") # Unnecessary detail
        return f"Error: Command not found: {e}"
    except OSError as e:
        print(f"Error: OS error: {e}") # Unnecessary detail
        return f"Error: OS error: {e}"
    except Exception as e:
        print(f"An unexpected error occurred: {e}") # Unnecessary detail
        return "Error: An unexpected error occurred during command execution."


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <index>")
        sys.exit(1)

    index_string = sys.argv[1]
    result = get_element_from_array(index_string)
    print(f"Element at index {index_string}: {result}")

    # Example of executing a safe command
    safe_command_result = execute_safe_command("safe_command_1")
    print(f"Safe command result: {safe_command_result}")

