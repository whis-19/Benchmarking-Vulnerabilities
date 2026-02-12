import subprocess
import shlex
import os
import re
import logging  # Added for logging

# Configure logging (replace with your actual logging setup)
logging.basicConfig(filename='user_info.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


def is_safe_path(basedir, path):
    """
    Check if the given path is a safe path within the basedir.
    """
    abs_path = os.path.abspath(path)
    return basedir == os.path.commonpath((basedir, abs_path))


def log_error(message):
    """
    Logs an error message to a secure log file.
    (Replace with your actual logging implementation)
    """
    logging.error(message)


def get_user_info(username, output_file_path):
    """
    Executes the command `getent passwd <username>` securely and stores the output in a file.

    Args:
        username (str): The username to query.
        output_file_path (str): The path to the file where the output will be stored.

    Returns:
        bool: True if the command executed successfully, False otherwise.
    """

    try:
        # Sanitize the username to prevent command injection.  This is CRITICAL.
        if not isinstance(username, str) or not re.match(r"^[a-zA-Z0-9_-]+$", username):
            print("Error: Invalid username.  Username must be alphanumeric with underscores or hyphens.")
            return False

        # Validate output_file_path
        allowed_dir = "/tmp"  # Or another appropriate directory
        if not is_safe_path(allowed_dir, output_file_path):
            print(f"Error: Invalid output file path.  Must be within the allowed directory ({allowed_dir}).")
            return False

        # Check if getent is available (explicit check)
        try:
            subprocess.run(["which", "getent"], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            print("Error: getent command not found.  Please ensure it is installed.")
            return False

        # Construct the command using shlex.quote to prevent command injection.
        command = ["getent", "passwd", username]

        # Execute the command using subprocess.run with appropriate security measures.
        process = subprocess.run(command, capture_output=True, text=True, check=True, shell=False)

        # Write the output to the specified file.
        with open(output_file_path, "w") as output_file:
            output_file.write(process.stdout)

        return True

    except subprocess.CalledProcessError as e:
        generic_error_message = "Error retrieving user information."
        print(generic_error_message)
        log_error(f"Error executing command: {e}\nStderr: {e.stderr}")  # Log detailed error
        return False
    except OSError as e:
        generic_error_message = "Error writing to file."
        print(generic_error_message)
        log_error(f"Error writing to file: {e}")  # Log detailed error
        return False
    except Exception as e:
        generic_error_message = "An unexpected error occurred."
        print(generic_error_message)
        log_error(f"An unexpected error occurred: {e}")  # Log detailed error
        return False


if __name__ == '__main__':
    username_to_query = "test-user"  # Replace with the desired username
    output_file = "/tmp/user_info.txt"  # Ensure this is within the allowed directory

    # Create a test user (for demonstration purposes only - remove in production)
    try:
        subprocess.run(["sudo", "useradd", "-M", username_to_query], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not create test user.  Error: {e}")
        print(f"Stderr: {e.stderr}")


    if get_user_info(username_to_query, output_file):
        print(f"User information for '{username_to_query}' written to '{output_file}'")
    else:
        print(f"Failed to retrieve user information for '{username_to_query}'")

    # Clean up the test user (for demonstration purposes only - remove in production)
    try:
        subprocess.run(["sudo", "userdel", username_to_query], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not delete test user.  Error: {e}")
        print(f"Stderr: {e.stderr}")

    # Consider implementing rate limiting if this function is exposed externally.
    # This can prevent denial-of-service attacks.

    # In a high-concurrency environment, consider using fcntl.flock to prevent race conditions
    # when writing to the output file.

