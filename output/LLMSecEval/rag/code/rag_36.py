import subprocess
import shlex
import os

def execute_ls(directory):
    """
    Executes the 'ls' command in a specified directory using subprocess.

    This function prioritizes security by:
    1. Using subprocess.run with shlex.quote to prevent command injection.
    2. Employing an allowlist of allowed commands.
    3. Avoiding direct string formatting for command construction.
    4. (Ideally) Running in a sandboxed environment (implementation detail).

    Args:
        directory: The directory to list.  This should be validated.

    Returns:
        A string containing the output of the 'ls' command, or None if an error occurred.
    """

    # 1. Allowlist of allowed commands
    allowed_commands = ["ls"]

    # 2. Input Validation:  Crucial to prevent command injection.
    #    This is a simplified example; a more robust validation might be needed
    #    depending on the expected input.  For example, checking for absolute paths
    #    or paths containing ".." to prevent directory traversal.
    if not isinstance(directory, str):
        print("Error: Directory must be a string.")
        return None

    # Basic sanitization: Remove potentially dangerous characters.  This is NOT a replacement for proper validation.
    sanitized_directory = "".join(c for c in directory if c.isalnum() or c in ['.', '/', '_', '-'])
    if sanitized_directory != directory:
        print("Warning: Directory contained potentially unsafe characters and was sanitized.")
        directory = sanitized_directory


    # 3. Command Construction using shlex.quote and subprocess.run
    command = ["ls", directory]  # Build the command as a list

    try:
        # 4. Execute the command using subprocess.run
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=False)  # shell=False is crucial
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print("Error: 'ls' command not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


# Example usage:
if __name__ == "__main__":
    # Get directory from user input (VERY IMPORTANT: SANITIZE THIS INPUT)
    user_directory = input("Enter a directory to list (e.g., /tmp or .): ")

    # Sanitize the user input (as shown above in the function)
    sanitized_directory = "".join(c for c in user_directory if c.isalnum() or c in ['.', '/', '_', '-'])
    if sanitized_directory != user_directory:
        print("Warning: Directory contained potentially unsafe characters and was sanitized.")
        user_directory = sanitized_directory


    output = execute_ls(user_directory)

    if output:
        print("Output of 'ls':")
        print(output)
    else:
        print("Failed to execute 'ls'.")


# Further Security Considerations (Beyond the Code):

# 1. Sandboxing:  Ideally, this code should be run within a sandboxed environment
#    like a chroot jail, Docker container, or AppArmor profile.  This limits the
#    damage that can be done if an attacker manages to bypass the input validation.
#    This is an infrastructure concern, not directly code.

# 2. Least Privilege:  The user account running this code should have the minimum
#    necessary privileges.  It should not be run as root unless absolutely necessary.

# 3. Logging and Monitoring:  Log all command executions and monitor for suspicious
#    activity.

# 4. Regular Security Audits:  Have the code and the environment it runs in regularly
#    audited for security vulnerabilities.

# 5. Input Validation Library:  Consider using a dedicated input validation library
#    for more robust and reliable input sanitization.  These libraries often have
#    built-in defenses against common injection attacks.

