import subprocess
import shlex
import os
import re  # Import the regular expression module
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Define an allowlist of allowed commands
ALLOWED_COMMANDS = ["ls", "pwd", "date", "echo"]  # Add more as needed, but be VERY careful

# Define allowed directories for path traversal prevention
ALLOWED_DIRECTORIES = ["/tmp", "/home/user/safe_directory"]  # Example safe directories

def execute_command(command_string):
    """
    Executes a command string, but only if it's in the allowlist and constructed safely.

    Args:
        command_string: The command string to execute.

    Returns:
        A tuple containing the return code, stdout, and stderr of the command.
        Returns None if the command is not allowed or an error occurs.
    """

    try:
        # 1. Command Validation:  Check if the base command is in the allowlist
        command_parts = shlex.split(command_string)  # Split into command and arguments
        base_command = command_parts[0]

        if base_command not in ALLOWED_COMMANDS:
            logging.warning(f"Attempted execution of disallowed command: {base_command}")
            print(f"Error: Command '{base_command}' is not allowed.")
            return None

        # 2. Input Sanitization and Validation (Command-Specific)
        sanitized_command_parts = [base_command]  # Always include the base command
        if base_command == "ls":
            for part in command_parts[1:]:
                # Example: Validate filename (alphanumeric, underscore, dot, and path traversal prevention)
                if re.match(r"^[a-zA-Z0-9_./-]+$", part):
                    abs_path = os.path.abspath(part)
                    is_allowed = False
                    for allowed_dir in ALLOWED_DIRECTORIES:
                        if abs_path.startswith(allowed_dir):
                            is_allowed = True
                            break
                    if is_allowed:
                        sanitized_command_parts.append(part)
                    else:
                        logging.warning(f"Path traversal attempt detected: {part}")
                        print(f"Error: Path '{part}' is outside the allowed directories.")
                        return None
                else:
                    logging.warning(f"Invalid filename argument for ls: {part}")
                    print(f"Error: Invalid filename '{part}'.")
                    return None

        elif base_command == "date":
            # Example: No arguments allowed for date
            if len(command_parts) > 1:
                logging.warning(f"Arguments provided to date command: {command_parts[1:]}")
                print("Error: 'date' command does not accept arguments in this context.")
                return None
            # No sanitization needed, just the command itself
            pass

        elif base_command == "echo":
            # Example: Sanitize echo arguments to prevent injection
            for part in command_parts[1:]:
                # Allow only alphanumeric and spaces for echo
                sanitized_part = ''.join(c for c in part if c.isalnum() or c == ' ')
                if sanitized_part != part:
                    logging.warning(f"Sanitized echo argument: {part} -> {sanitized_part}")
                    print(f"Warning: Argument '{part}' for echo was sanitized.")
                sanitized_command_parts.append(sanitized_part)

        elif base_command == "pwd":
            # No arguments allowed for pwd
            if len(command_parts) > 1:
                logging.warning(f"Arguments provided to pwd command: {command_parts[1:]}")
                print("Error: 'pwd' command does not accept arguments in this context.")
                return None
            # No sanitization needed, just the command itself
            pass

        else:
            # Should never reach here, but handle it gracefully
            logging.error(f"Unexpected command: {base_command}")
            print(f"Error: Unexpected command '{base_command}'. This should not happen.")
            return None

        # Reconstruct the command string with sanitized parts
        sanitized_command_string = ' '.join(sanitized_command_parts)

        # 3. Use subprocess.run with shlex.split for safe execution
        #    - shell=False is crucial to avoid shell injection
        #    - capture_output=True captures stdout and stderr
        #    - text=True decodes the output as text
        logging.info(f"Executing command: {sanitized_command_string}")
        result = subprocess.run(shlex.split(sanitized_command_string), capture_output=True, text=True, shell=False, check=False)

        # 4. Output Sanitization (Example - remove potential sensitive data)
        stdout = result.stdout
        stderr = result.stderr

        # Example: Remove any lines containing "password" from stdout
        stdout = "\n".join(line for line in stdout.splitlines() if "password" not in line.lower())

        # 5. Logging
        logging.info(f"Command executed: {sanitized_command_string}, Return Code: {result.returncode}")

        return result.returncode, stdout, stderr

    except FileNotFoundError as e:
        logging.error(f"FileNotFoundError: {e}")
        print(f"Error: File not found: {e}")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        print(f"An error occurred: {e}")
        return None


if __name__ == '__main__':
    # Example usage:

    # 1. Safe usage with a hardcoded command and argument
    filename = "/tmp/myfile.txt"  # Example filename (can be from external source, but sanitize!)
    command_str = f"ls -l {filename}"  # Construct the command string
    result = execute_command(command_str)

    if result:
        return_code, stdout, stderr = result
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")
    else:
        print("Command execution failed or was not allowed.")


    # 2.  Unsafe usage (demonstration of why sanitization is needed)
    #    -  NEVER do this in production code!
    #    -  This is vulnerable to command injection if `user_input` is not properly sanitized.
    # user_input = "; rm -rf /"  # DANGEROUS!  Example of command injection
    # command_str = f"ls {user_input}"
    # result = execute_command(command_str) # This would be disastrous without sanitization

    # 3.  Example with a different allowed command
    result = execute_command("date")
    if result:
        return_code, stdout, stderr = result
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")
    else:
        print("Command execution failed or was not allowed.")

    # 4. Example of an invalid command
    result = execute_command("rm -rf /") # Not in the allowlist
    if result is None:
        print("Command was correctly blocked.")

    # 5. Example of bypass attempt (filename with special characters)
    # This is still vulnerable if `ls` interprets the filename in a dangerous way
    # Even though the characters are allowed, `ls` might still be tricked.
    # This highlights the limitation of character-based sanitization.
    filename_bypass = "file; touch PWNED" # Attempt to create a file
    command_str = f"ls -l {filename_bypass}"
    result = execute_command(command_str)
    if result:
        return_code, stdout, stderr = result
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")
    else:
        print("Command execution failed or was not allowed.")

    # 6. Example of an argument with invalid characters
    result = execute_command("ls -l inv@lid")
    if result is None:
        print("Command with invalid argument was correctly blocked.")

    # 7. Example of path traversal attempt
    result = execute_command("ls -l ../../../etc/passwd")
    if result is None:
        print("Path traversal attempt correctly blocked.")

    # 8. Example of pwd command
    result = execute_command("pwd")
    if result:
        return_code, stdout, stderr = result
        print(f"Return Code: {return_code}")
        print(f"Stdout: {stdout}")
        print(f"Stderr: {stderr}")
    else:
        print("Command execution failed or was not allowed.")

    # 9. Example of pwd command with arguments (should be blocked)
    result = execute_command("pwd /tmp")
    if result is None:
        print("pwd command with arguments correctly blocked.")

