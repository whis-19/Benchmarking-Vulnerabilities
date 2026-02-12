import sys
import os
import subprocess
import shlex
import re
import logging
import unicodedata
import secrets  # For secure random number generation
import tempfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_ARGUMENT_LENGTH = 2048  # Example maximum argument length

def sanitize_filename(filename):
    """Sanitizes a filename to prevent path traversal."""
    # Normalize the path
    normalized_path = os.path.normpath(filename)

    # Resolve symbolic links
    real_path = os.path.realpath(normalized_path)

    # Check if the path is within an allowed directory
    allowed_dir = "/tmp/allowed_directory"  # Replace with your allowed directory
    if not real_path.startswith(allowed_dir):
        raise ValueError("Filename is outside the allowed directory.")

    return real_path

def execute_command(command, argument):
    """
    Executes a pre-defined command with a sanitized argument.
    """

    allowed_commands = ["my_safe_command"]  # ONLY include absolutely necessary commands
    if command not in allowed_commands:
        logging.error(f"Attempted to execute disallowed command: {command}")
        print(f"Error: Command '{command}' is not allowed.", file=sys.stderr)
        return

    # Input Normalization
    argument = unicodedata.normalize('NFKC', argument)

    # Argument Length Limit
    if len(argument) > MAX_ARGUMENT_LENGTH:
        logging.error(f"Argument exceeds maximum length: {len(argument)}")
        print("Error: Argument too long.", file=sys.stderr)
        return


    if command == "my_safe_command":
        # Contextual validation for my_safe_command
        try:
            sanitized_arg = sanitize_filename(argument)
        except ValueError as e:
            logging.error(f"Invalid filename: {argument} - {e}")
            print(f"Error: Invalid filename: {e}", file=sys.stderr)
            return

        full_command = [command, sanitized_arg]
        quoted_argument = shlex.quote(sanitized_arg) # Defense in depth - quote even after sanitization

    # Sandbox (replace with a REAL sandbox implementation)
    print("Simulating sandbox environment (no actual sandboxing).  IMPLEMENT A REAL SANDBOX!")
    print("Consider using Docker, virtual machines, or seccomp-bpf for real sandboxing.")

    try:
        # Create a temporary directory for the subprocess
        temp_dir = tempfile.mkdtemp()

        # Example of subprocess hardening (Linux only - requires setup)
        # def drop_privileges():
        #     # Implement logic to drop privileges (change user/group)
        #     # This is a complex topic and requires careful setup.
        #     # Incorrect use of preexec_fn can introduce vulnerabilities.
        #     pass

        process = subprocess.Popen(
            full_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # executable=command,  # Redundant - the first element of full_command is the executable
            # preexec_fn=drop_privileges,  # Uncomment and implement for privilege dropping
            close_fds=True,
            cwd=temp_dir  # Set a safe working directory
        )
        stdout, stderr = process.communicate(timeout=10)  # Add a timeout

        if stdout:
            print(stdout.decode('utf-8'))
        if stderr:
            print(stderr.decode('utf-8'), file=sys.stderr)

        if process.returncode != 0:
            logging.error(f"Command {command} exited with code {process.returncode}")
            print(f"Error: Command exited with code {process.returncode}", file=sys.stderr)

    except FileNotFoundError:
        logging.error(f"Command not found: {command}")
        print(f"Error: Command '{command}' not found.", file=sys.stderr)
    except OSError as e:
        logging.error(f"Error executing command: {command} - {e}")
        print(f"Error executing command: {e}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        process.kill()
        logging.error(f"Command {command} timed out.")
        print("Error: Command timed out.", file=sys.stderr)
    finally:
        # Clean up the temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        argument = sys.argv[1]
        execute_command("my_safe_command", argument)
    else:
        print("Usage: python script.py <argument>", file=sys.stderr)

