import subprocess
import os
import shlex

def get_user_info(username, output_file):
    """
    Retrieves user information using getent passwd and writes the output to a file.

    Args:
        username (str): The username to look up.  This MUST be carefully validated.
        output_file (str): The path to the file where the output will be written.
                           This MUST be carefully validated to prevent path traversal.

    Returns:
        bool: True if the command executed successfully, False otherwise.
    """

    # Security: Validate username.  This is critical to prevent command injection.
    if not isinstance(username, str):
        print("Error: Username must be a string.")
        return False

    if not username.isalnum():  # Allow only alphanumeric characters
        print("Error: Username must be alphanumeric.")
        return False

    # Security: Validate output_file path to prevent path traversal.
    if not isinstance(output_file, str):
        print("Error: Output file must be a string.")
        return False

    if ".." in output_file:
        print("Error: Output file path cannot contain '..'.")
        return False

    # Security:  Restrict output file location to a safe directory.
    safe_directory = "/tmp/user_info"  # Example safe directory
    if not output_file.startswith(safe_directory):
        print(f"Error: Output file must be in the {safe_directory} directory.")
        return False

    # Ensure the safe directory exists
    try:
        os.makedirs(safe_directory, exist_ok=True)
    except OSError as e:
        print(f"Error creating directory {safe_directory}: {e}")
        return False

    # Security: Use subprocess.run with argument list.  Avoid shell=True.
    command = ["getent", "passwd", username]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Write the output to the specified file.
        with open(output_file, "w") as f:
            f.write(result.stdout)

        return True

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return False
    except OSError as e:
        print(f"Error writing to file: {e}")
        return False


if __name__ == '__main__':
    # Example usage (with validation):
    username = input("Enter username: ")
    output_file = "/tmp/user_info/user_data.txt"  # Fixed output file for testing

    if get_user_info(username, output_file):
        print(f"User information written to {output_file}")
    else:
        print("Failed to retrieve user information.")

