import sys
import os
import shlex  # For safe shell quoting (if absolutely necessary)

MAX_INDEX = 10  # Or whatever a reasonable maximum is
ALLOWED_DIRECTORY = "/path/to/allowed/directory"  # Define an allowed directory

def validate_index(argv):
    """
    Validates the index provided as a command-line argument.

    Args:
        argv: The list of command-line arguments (sys.argv).

    Returns:
        The validated index as an integer, or None if validation fails.
    """
    if len(argv) < 2:
        print("Error: Index argument is missing.")
        return None

    try:
        index = int(argv[1])
    except ValueError:
        print("Error: Index must be an integer.")
        return None

    if index < 0:
        print("Error: Index must be non-negative.")
        return None

    if index > MAX_INDEX:
        print(f"Error: Index exceeds maximum allowed value of {MAX_INDEX}.")
        return None

    if index >= len(argv):
        print("Error: Index out of bounds.")
        return None

    return index


def safe_command_execution(argv, index):
    """
    Demonstrates safe command execution using subprocess.run.

    Args:
        argv: The list of command-line arguments (sys.argv).
        index: The validated index.

    Returns:
        None.  Prints the output of the command or an error message.
    """

    if index is None:
        return  # Index validation failed

    try:
        filename = argv[index]
    except IndexError:
        print("Error: Index out of bounds after validation.  This should not happen.")
        return

    # Path Traversal Prevention:
    abs_path = os.path.abspath(os.path.normpath(filename))

    if not abs_path.startswith(ALLOWED_DIRECTORY):
        print("Error: Filename is not within the allowed directory.")
        return

    command = ["ls", "-l", abs_path]  # Pass as a list!
    print(f"Executing: {command}")

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)  # check=True raises exception on non-zero exit code
        print(f"Stdout: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        print(f"Error: Command not found: {command[0]}") # More specific error message


def unsafe_command_execution(argv, index):
    """
    Demonstrates UNSAFE command execution using shell=True.  DO NOT USE IN PRODUCTION.

    Args:
        argv: The list of command-line arguments (sys.argv).
        index: The validated index.

    Returns:
        None.  Prints the output of the command or an error message.
    """

    if index is None:
        return  # Index validation failed

    try:
        filename = argv[index]
    except IndexError:
        print("Error: Index out of bounds after validation.  This should not happen.")
        return

    # Path Traversal Prevention:
    abs_path = os.path.abspath(os.path.normpath(filename))

    if not abs_path.startswith(ALLOWED_DIRECTORY):
        print("Error: Filename is not within the allowed directory.")
        return

    # UNSAFE: Using shell=True.  Only for demonstration purposes.
    command = f"ls -l {shlex.quote(abs_path)}"  # Quote the filename!
    print(f"Executing (UNSAFE): {command}")

    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)  # check=True raises exception on non-zero exit code
        print(f"Stdout: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stdout: {e.stdout}")
        print(f"Stderr: {e.stderr}")
    except FileNotFoundError:
        print(f"Error: Command not found: ls") # More specific error message


if __name__ == "__main__":
    index = validate_index(sys.argv)

    # Demonstrate safe command execution
    safe_command_execution(sys.argv, index)

    # Demonstrate unsafe command execution (DO NOT USE IN PRODUCTION)
    # unsafe_command_execution(sys.argv, index)

