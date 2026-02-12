import subprocess
import shlex
import os

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
        if not isinstance(username, str) or not username.isalnum():
            print("Error: Invalid username.  Username must be alphanumeric.")
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
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return False
    except OSError as e:
        print(f"Error writing to file: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False


if __name__ == '__main__':
    username_to_query = "testuser"  # Replace with the desired username
    output_file = "user_info.txt"

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

