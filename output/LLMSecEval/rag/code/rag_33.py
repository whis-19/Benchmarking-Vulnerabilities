import subprocess
import shlex
import os

def get_user_info(username, output_file):
    """
    Retrieves user information using getent passwd and writes the output to a file.

    This function prioritizes security by:
    - Using a strict allowlist for the username.
    - Using subprocess.run with shlex.quote to prevent command injection.
    - Executing the command in a sandboxed environment (optional, see below).
    - Using a pre-defined allowlist of commands.

    Args:
        username (str): The username to look up.
        output_file (str): The path to the file where the output will be written.

    Returns:
        bool: True if the command executed successfully, False otherwise.
    """

    # 1. Input Validation: Strict Allowlist for Username
    if not is_valid_username(username):
        print("Error: Invalid username.  Username must contain only lowercase letters, numbers, underscores, and hyphens.")
        return False

    # 2. Command Allowlist
    allowed_commands = ["getent"]
    command = "getent"  # Hardcoded command

    if command not in allowed_commands:
        print("Error: Command not allowed.")
        return False

    # 3. Command Construction with shlex.quote
    try:
        quoted_username = shlex.quote(username)
        cmd = [command, "passwd", quoted_username]
    except Exception as e:
        print(f"Error quoting username: {e}")
        return False

    # 4. Execute Command with subprocess.run
    try:
        # Optional: Sandbox environment (e.g., chroot)
        #  This requires setting up a chroot environment beforehand.
        #  Example:
        #  chroot_path = "/path/to/chroot"
        #  cmd = ["chroot", chroot_path] + cmd

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # 5. Write Output to File
        with open(output_file, "w") as f:
            f.write(result.stdout)

        print(f"User information for {username} written to {output_file}")
        return True

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return False
    except FileNotFoundError:
        print("Error: getent command not found.  Make sure it is in your PATH.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


def is_valid_username(username):
    """
    Validates the username against a strict allowlist.
    """
    import re
    pattern = r"^[a-z0-9_-]+$"  # Only lowercase letters, numbers, underscores, and hyphens
    return bool(re.match(pattern, username))


if __name__ == '__main__':
    # Example Usage
    username = "testuser"  # Replace with the desired username
    output_file = "user_info.txt"

    # Get username from user input (example, but be careful with user input in real applications)
    # username = input("Enter username: ")

    if get_user_info(username, output_file):
        print("Operation completed successfully.")
    else:
        print("Operation failed.")

