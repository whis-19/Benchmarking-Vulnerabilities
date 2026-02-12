import subprocess
import sys
import os

def get_user_id(username):
    """
    Runs the 'id' command with the given username and returns the exit status.
    This function uses a strict allowlist for commands and input validation to prevent command injection.
    """

    # 1. Allowlist of allowable commands
    allowed_commands = ["id"]

    # 2. Statically created command (base command)
    command = "id"

    if command not in allowed_commands:
        print("Error: Command not allowed.")
        return 1  # Non-zero exit status indicating failure

    # 3. Input validation and sanitization (strict allowlist for username characters)
    allowed_username_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"  # Example allowlist
    sanitized_username = "".join(c for c in username if c in allowed_username_chars)

    if sanitized_username != username:
        print("Error: Invalid username.  Only alphanumeric characters and underscores are allowed.")
        return 1

    # 4. Construct the command with the sanitized username
    full_command = [command, sanitized_username]

    # 5. Execute the command using subprocess.run (vetted library)
    try:
        result = subprocess.run(full_command, capture_output=True, text=True, check=False)  # check=False to get exit code even on failure

        # Print the output for debugging purposes (remove in production if not needed)
        print(f"Command output: {result.stdout}")
        print(f"Command error: {result.stderr}")

        return result.returncode
    except FileNotFoundError:
        print("Error: 'id' command not found.")
        return 1
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    exit_status = get_user_id(username)
    print(f"Exit status: {exit_status}")
    sys.exit(exit_status)

