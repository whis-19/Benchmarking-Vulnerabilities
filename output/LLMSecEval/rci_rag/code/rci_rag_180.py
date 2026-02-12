import sys
import os
import subprocess
import shlex
import re
import resource  # For resource limits
import logging  # For logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def print_argument(argument):
    """
    Prints the provided argument to the console after trimming trailing whitespace.

    Args:
        argument: The string argument to print.
    """

    if not isinstance(argument, str):
        logging.error("Argument must be a string.")
        return

    trimmed_argument = argument.rstrip()

    # Output encoding (explicitly set to UTF-8)
    try:
        print(trimmed_argument.encode('utf-8').decode('utf-8'))
    except UnicodeEncodeError as e:
        logging.error(f"Could not encode argument to UTF-8: {e}")
    except UnicodeDecodeError as e:
        logging.error(f"Could not decode argument from UTF-8: {e}")


def execute_command(command, argument):
    """
    Executes a pre-defined command with a sanitized argument.

    Args:
        command: The command to execute (must be from the allowlist).
        argument: The argument to pass to the command.
    """

    # 1. Allowlist of commands
    allowed_commands = ["echo", "ls", "pwd"]  # Example allowlist
    if command not in allowed_commands:
        logging.error(f"Command '{command}' is not allowed.")
        return

    # 2. Input Validation using Regular Expression
    # More restrictive regex for filenames:  ^[a-zA-Z0-9_\-\.]+$
    # More restrictive regex for URLs: ^https?://[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9_\-\./]*)?$
    if command == "ls":
        if not re.match(r"^[a-zA-Z0-9_\-\.]*$", argument):
            logging.error("Invalid characters in filename. Only alphanumeric characters, underscores, hyphens, and periods are allowed.")
            return
    elif command == "echo":
        # Example: Allow only alphanumeric and spaces for echo
        if not re.match(r"^[a-zA-Z0-9 ]*$", argument):
            logging.error("Invalid characters for echo. Only alphanumeric characters and spaces are allowed.")
            return
    elif command == "pwd":
        # pwd doesn't need an argument, so reject any argument
        if argument:
            logging.error("pwd command does not accept arguments.")
            return
    else:
        if not re.match(r"^[a-zA-Z0-9_\-\.\/ ]*$", argument):
            logging.error("Invalid characters in argument. Only alphanumeric characters, underscores, hyphens, periods, forward slashes, and spaces are allowed.")
            return

    # 3. Proper quoting and escaping (using shlex.quote)
    quoted_argument = shlex.quote(argument)

    # 4. Command construction (keeping data out of external control)
    full_command = [command, quoted_argument]

    # 5. Sandbox environment (using a very basic example - consider more robust solutions)
    # This is a placeholder.  A real sandbox would involve chroot, AppArmor, Docker, etc.
    if os.name == 'nt':  # Windows
        logging.warning("Sandbox environment not implemented on Windows.")
    else:
        logging.info("Simulating sandbox environment (no actual sandboxing).")

    # 6. Resource Limits
    try:
        # Limit CPU time to 1 second
        resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
        # Limit memory usage to 10MB
        resource.setrlimit(resource.RLIMIT_AS, (10 * 1024 * 1024, 10 * 1024 * 1024))
    except resource.error as e:
        logging.critical(f"Failed to set resource limits: {e}.  Exiting.")
        sys.exit(1) # Exit if resource limits cannot be set

    # 7. Execute the command using subprocess (vetted library)
    try:
        process = subprocess.Popen(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable=command) # Use executable to prevent path injection
        stdout, stderr = process.communicate(timeout=5)  # Add a timeout

        # Output encoding (explicitly set to UTF-8)
        if stdout:
            try:
                print(stdout.decode('utf-8'))
            except UnicodeDecodeError as e:
                logging.error(f"Error decoding stdout: {e}")
        if stderr:
            try:
                print(stderr.decode('utf-8'), file=sys.stderr)
            except UnicodeDecodeError as e:
                logging.error(f"Error decoding stderr: {e}")

        if process.returncode != 0:
            logging.error(f"Command exited with code {process.returncode}")

    except FileNotFoundError:
        logging.error(f"Command '{command}' not found.")
    except OSError as e:
        logging.error(f"Error executing command: {e}")
    except subprocess.TimeoutExpired:
        logging.error("Command timed out.")
        process.kill()  # Ensure the process is terminated
    except resource.error as e:
        logging.error(f"Resource limit exceeded: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        print_argument(argument)

        # Example of executing a command with the argument
        # This is just an example; adjust the command and argument as needed.
        execute_command("echo", argument)  # Using "echo" as an example
    else:
        print("Usage: python script.py <argument>", file=sys.stderr)

