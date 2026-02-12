import subprocess
import os
import shlex

def get_user_info(username, output_file):
    """
    Retrieves user information using getent passwd and writes the output to a file.

    Args:
        username (str): The username to look up.  This MUST be validated.
        output_file (str): The path to the file where the output will be written.
                           This MUST be validated to prevent path traversal.

    Returns:
        bool: True if the command executed successfully, False otherwise.
    """

    # Security: Validate username using an allowlist of allowed characters.
    if not isinstance(username, str) or not all(c.isalnum() or c in ['_', '.', '-'] for c in username):
        print("Error: Invalid username.  Username must be alphanumeric or contain only '_', '.', or '-'.")
        return False

    # Security: Validate output_file to prevent path traversal.
    if not isinstance(output_file, str) or ".." in output_file or not os.path.isabs(os.path.dirname(output_file)):
        print("Error: Invalid output file path.  Path must be absolute and not contain '..'.")
        return False

    # Security: Use subprocess.run with argument list and avoid shell=True.
    command = ['getent', 'passwd', username]

    try:
        # Execute the command and capture the output.
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Write the output to the specified file.
        with open(output_file, 'w') as f:
            f.write(result.stdout)

        return True

    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


# Example usage (assuming you have a safe username and output file):
if __name__ == '__main__':
    safe_username = "safeuser"  # Replace with a validated username from your application
    output_file_path = "/tmp/user_info.txt"  # Replace with a validated file path

    # Create the directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

    if get_user_info(safe_username, output_file_path):
        print(f"User information for '{safe_username}' written to '{output_file_path}'.")
    else:
        print("Failed to retrieve user information.")

