import subprocess
import shlex
import os
import logging
import resource  # For resource limits

# Configure logging
logging.basicConfig(level=logging.ERROR, filename='get_user_info.log', format='%(asctime)s - %(levelname)s - %(message)s', maxBytes=1024*1024, backupCount=5) # Log rotation

def get_user_info(username):
    """
    Retrieves user information using the `getent passwd` command in a secure manner.

    Args:
        username (str): The username to look up.  This input is carefully validated.

    Returns:
        dict: A dictionary containing user information, or None if an error occurred.
    """

    # 1. Input Validation: Strict Allowlist
    # Only allow alphanumeric characters and underscores in the username.
    if not all(c.isalnum() or c == '_' for c in username):
        print("Error: Invalid username. Username contains disallowed characters. Only alphanumeric characters and underscores are allowed.")
        logging.warning(f"Invalid username attempt: {username}") # Log invalid username attempts
        return None

    # 2. Command Allowlist
    allowed_commands = ["getent"]  # Only allow 'getent'
    command = "getent"
    if command not in allowed_commands:
        print("Error: Command not allowed.")
        logging.error(f"Attempted to execute disallowed command: {command}")
        return None

    # 3. Argument Sanitization and Quoting (using shlex.quote)
    # Use shlex.quote to properly escape the username for the shell.
    # This prevents command injection.
    quoted_username = shlex.quote(username)

    # 4. Construct the command with validated and quoted arguments.
    full_command = f"{command} passwd {quoted_username}"

    # 5. Execute the command using subprocess.run with shell=False (critical for security)
    #    and capture the output.
    try:
        # Set resource limits (optional, but good practice)
        resource.setrlimit(resource.RLIMIT_CPU, (1, 1))  # Limit CPU time to 1 second
        resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100)) # Limit address space to 100MB

        result = subprocess.run(full_command, shell=False, capture_output=True, text=True, check=True, executable='/usr/bin/getent') # Specify full path to getent
        output = result.stdout
        if not output.strip():  # Check if output is empty after removing leading/trailing whitespace
            print("Error: No output from getent. User may not exist.")
            logging.error(f"No output from getent for username: {username}")
            return None

        # Parse the output and return only the necessary information
        parts = output.strip().split(":")
        if len(parts) >= 7:
            user_info = {
                "username": parts[0],
                "uid": parts[2],
                "gid": parts[3],
                "home_directory": parts[5],
                "shell": parts[6]
            }
            return user_info
        else:
            logging.warning(f"Unexpected getent output format: {output}")
            print("Error: Unexpected output format from getent.")
            return None


    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
        logging.error(f"Stderr: {e.stderr}")
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: getent command not found.  Ensure it is installed and in /usr/bin.")
        logging.error("getent command not found.")
        return None
    except resource.error as e:
        print(f"Resource limit exceeded: {e}")
        logging.error(f"Resource limit exceeded: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        logging.exception(f"An unexpected error occurred: {e}") # Log the full exception traceback
        return None


# Example usage:
if __name__ == "__main__":
    username = input("Enter username: ")
    user_info = get_user_info(username)

    if user_info:
        print("User information:")
        # Print only the information you need
        print(f"Username: {user_info['username']}")
        print(f"UID: {user_info['uid']}")
        print(f"Home Directory: {user_info['home_directory']}")
        print("Consider using SAST and DAST tools for further security auditing.")
    else:
        print("Failed to retrieve user information.")
        print("Consider using SAST and DAST tools for further security auditing.")

    print("For production environments, consider sandboxing (chroot, AppArmor, Docker) for enhanced security.")

