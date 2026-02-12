import subprocess
import shlex
import os  # For environment variable access (if needed)

def execute_command(command_string):
    """
    Executes a command string safely using subprocess.

    Args:
        command_string: The command string to execute.

    Returns:
        A CompletedProcess object containing the results of the command execution,
        or None if the command is invalid or execution fails.
    """

    # 1. Split the command string into parts using shlex for proper tokenization
    command_parts = shlex.split(command_string)

    # 2. Validate the command (strict allowlist)
    allowed_commands = ["ls", "grep", "cat", "head", "tail", "wc", "sort", "uniq", "find"]  # Example allowlist
    if not command_parts:
        print("Error: Empty command.")
        return None

    command = command_parts[0]
    if command not in allowed_commands:
        print(f"Error: Command '{command}' is not allowed.")
        return None

    # 3. Sanitize arguments (strict allowlist and length limits)
    sanitized_command_parts = [command]
    for part in command_parts[1:]:  # Iterate through arguments
        sanitized_part = ''.join(c for c in part if c.isalnum() or c in ['.', '/', '-', '_'])  # Strict allowlist
        if len(sanitized_part) > 256:  # Example length limit
            print(f"Error: Argument '{part}' is too long.")
            return None
        sanitized_command_parts.append(sanitized_part)

    # 4. Reconstruct the sanitized command string (for logging/auditing)
    sanitized_command_string = ' '.join(sanitized_command_parts)
    print(f"Sanitized command: {sanitized_command_string}") # Log the sanitized command

    # 5. Execute the command using subprocess.run with shell=False
    # Consider adding a timeout to prevent denial-of-service attacks
    # Example: result = subprocess.run(shlex.split(sanitized_command_string), capture_output=True, text=True, shell=False, check=False, timeout=10)
    try:
        result = subprocess.run(shlex.split(sanitized_command_string), capture_output=True, text=True, shell=False, check=False, encoding='utf-8', errors='ignore') # or 'replace'
        # The 'encoding' and 'errors' arguments handle potential decoding issues.
        # 'errors='ignore'' will silently drop characters that can't be decoded.
        # 'errors='replace'' will replace them with a replacement character (usually '?').
        # The choice depends on the specific application and how you want to handle invalid characters.

        # Check the return code
        if result.returncode != 0:
            print(f"Command failed with return code: {result.returncode}")
            print(f"Standard Error:\n{result.stderr}")

        return result

    except subprocess.TimeoutExpired:
        print("Error: Command timed out.")
        return None
    except FileNotFoundError:
        print(f"Error: Command '{command}' not found.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

# Example Usage
if __name__ == "__main__":
    # Safe usage
    command = "ls -l /tmp"
    result = execute_command(command)
    if result:
        print(f"Standard Output:\n{result.stdout}")

    # Another safe usage
    command = "grep 'hello' /tmp/test.txt"
    result = execute_command(command)
    if result:
        print(f"Standard Output:\n{result.stdout}")

    # Unsafe usage (commented out to prevent accidental execution)
    # command = "ls -l; rm -rf /"  # This is extremely dangerous!
    # result = execute_command(command)
    # if result:
    #     print(f"Standard Output:\n{result.stdout}")

    # Example of command not in allowlist
    command = "rm -rf /tmp/*"
    result = execute_command(command)
    if result:
        print(f"Standard Output:\n{result.stdout}")

    # Example of argument too long
    long_argument = "A" * 300
    command = f"ls {long_argument}"
    result = execute_command(command)
    if result:
        print(f"Standard Output:\n{result.stdout}")

    # Example with encoding issues
    command = "cat test_encoding.txt" # Create a file with non-UTF-8 characters for testing
    result = execute_command(command)
    if result:
        print(f"Standard Output:\n{result.stdout}")

    # Example with timeout
    # command = "sleep 10" # Create a command that takes a long time
    # result = execute_command(command)
    # if result:
    #     print(f"Standard Output:\n{result.stdout}")

# Production Considerations (Important!)
# --------------------------------------
# * Sandboxing:  Use sandboxing technologies (e.g., Docker, VMs, chroot) to isolate the process
#               and limit its access to the system.
# * Logging:   Log all command executions, including the sanitized command string, the user who
#               initiated the command, the timestamp, and the result (stdout, stderr, return code).
# * Auditing:  Regularly audit the logs to identify any suspicious activity.
# * Principle of Least Privilege: Run the process with the minimum necessary privileges.  Avoid
#               running as root if possible.
# * Input Validation:  Validate all input to the application, not just the command string.  This
#               includes validating the user's identity and authorization.
# * Monitoring:  Monitor the system for any unusual activity, such as high CPU usage, excessive
#               disk I/O, or network connections to unexpected destinations.
# * Regular Security Updates: Keep the operating system and all software packages up to date with
#               the latest security patches.
# * Environment Variables: Be extremely careful when using environment variables within the command.
#               Sanitize them thoroughly if they are user-controlled.  Consider using a separate
#               environment for the subprocess.  Access environment variables using `os.environ.get()`
#               instead of directly interpolating them into the command string.
# * No eval() or exec():  Never use `eval()` or `exec()` to execute code based on user input.  These
#               functions are extremely dangerous and can lead to arbitrary code execution.
# * Resource Limits:  Implement resource limits (CPU, memory, disk I/O) to prevent denial-of-service
#               attacks.  The `timeout` argument to `subprocess.run` is one example of a resource limit.
# * Security Reviews:  Have the code reviewed by a security expert to identify any potential vulnerabilities.
# * Static Analysis:  Use static analysis tools to automatically detect potential security flaws in the code.

