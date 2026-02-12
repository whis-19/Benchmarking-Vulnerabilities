import subprocess
import shlex
import os
import logging

# Configure logging (adjust level as needed)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_user_info(username):
    """
    Retrieves user information using the `getent passwd` command in a secure manner.

    Args:
        username (str): The username to look up.  This input is carefully validated.

    Returns:
        str: The output of the `getent passwd` command, or None if an error occurred.
    """

    # 1. Input Validation: Strict Allowlist
    # Only allow alphanumeric characters and underscores in the username.
    if not all(c.isalnum() or c == '_' for c in username):
        logging.warning(f"Invalid username: {username}")
        print("Error: Invalid username. Only alphanumeric characters and underscores are allowed.")
        return None

    # 2. Command Allowlist
    allowed_commands = ["getent"]  # Only allow 'getent'
    command = "getent"

    if command not in allowed_commands:
        logging.error(f"Attempted to execute disallowed command: {command}")
        print("Error: Command not allowed.")
        return None

    # 3. Argument Construction with shlex.quote for escaping
    # Use shlex.quote to properly escape the username argument.
    try:
        quoted_username = shlex.quote(username)
    except AttributeError: # Python < 3.3
        quoted_username = "'" + username.replace("'", "'\\''") + "'" # Manual escaping

    full_command = ["getent", "passwd", quoted_username]

    # 4. Sandbox Environment (Optional, but highly recommended)
    # Consider using a chroot jail or similar sandboxing technique here.
    # This example doesn't implement a full sandbox, but highlights where it would go.
    # Example (Conceptual - requires setup):
    # with chroot("/path/to/jail"):
    #     process = subprocess.run(full_command, capture_output=True, text=True, check=True)

    # 5. Execute Command with subprocess.run (replaces system())
    try:
        logging.info(f"Executing command: {full_command}")
        process = subprocess.run(full_command, capture_output=True, text=True, check=True, timeout=5) # Added timeout
        output = process.stdout
        logging.debug(f"Command output: {output}")

        # 6. Information Leakage Mitigation: Parse and Filter Output
        # Only return the username and UID.  This is an example; adjust as needed.
        try:
            parts = output.split(":")
            if len(parts) > 2:  # Check if there are enough parts
                try:
                    uid = int(parts[2]) # Verify that parts[2] is an integer
                    filtered_output = f"Username: {parts[0]}, UID: {uid}"
                    logging.debug(f"Filtered output: {filtered_output}")
                    return filtered_output
                except ValueError:
                    logging.warning(f"UID is not an integer: {parts[2]}")
                    return "Error: Could not parse user information (invalid UID)."
            else:
                logging.warning(f"Unexpected output format from getent: {output}")
                return "Error: Could not parse user information."
        except IndexError:
            logging.warning(f"Unexpected output format from getent: {output}")
            return "Error: Could not parse user information."


    except subprocess.TimeoutExpired:
        logging.error("Command timed out.")
        print("Error: Command timed out.")
        return None
    except subprocess.CalledProcessError as e:
        # Sanitize stderr before logging
        error_message = "Command failed with code: {}".format(e.returncode)
        logging.error(error_message)
        print(error_message)
        return None
    except FileNotFoundError:
        logging.error("Error: 'getent' command not found.")
        print("Error: 'getent' command not found.  Ensure it is in your PATH.")
        return None

# Check for getent availability at the beginning of the script
if __name__ == "__main__":
    try:
        subprocess.run(["getent", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: 'getent' command not found.  Ensure it is in your PATH and installed.")
        exit(1)

    # Example Usage:
    username = input("Enter username: ")
    user_info = get_user_info(username)

    if user_info:
        print("User Information:")
        print(user_info)
    else:
        print("Failed to retrieve user information.")


    # Example of an invalid username:
    invalid_username = "user; rm -rf /"
    user_info = get_user_info(invalid_username) # This will be rejected due to input validation.

