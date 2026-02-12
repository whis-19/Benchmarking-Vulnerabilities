import subprocess
from flask import Flask, request
import shlex
import os

app = Flask(__name__)


@app.route('/execute')
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Execute it and return the command.
    '''
    command = request.args.get('command')

    if not command:
        return "Error: No command provided", 400

    # Input Validation and Sanitization:  Crucially important!
    # 1.  Whitelist approach:  Define allowed commands and parameters.
    # 2.  Parameter validation:  Check data types, ranges, and formats.
    # 3.  Avoid shell injection:  Use shlex.split() and subprocess.run() with shell=False.
    # 4.  Principle of Least Privilege:  Run the process with a restricted user account.
    # 5.  Logging:  Log all commands executed and their results for auditing.

    # Example of a whitelist approach (highly recommended):
    allowed_commands = {
        "ping": ["-c", "-n", "-i", "-w"],  # Allowed ping options
        "ls": ["-l", "-a", "-h"],  # Allowed ls options
        "cat": [] # Allow cat with no options
    }

    try:
        command_parts = shlex.split(command)  # Split into command and arguments
        base_command = command_parts[0]

        if base_command not in allowed_commands:
            return "Error: Command not allowed", 403

        # Validate arguments against the allowed options for the command
        allowed_options = allowed_commands[base_command]
        for i in range(1, len(command_parts)):
            if command_parts[i].startswith("-") and command_parts[i] not in allowed_options:
                return "Error: Invalid option for command", 403

        # Execute the command using subprocess.run with shell=False
        # and capture the output.  Use a timeout to prevent indefinite execution.
        process = subprocess.run(command_parts, capture_output=True, text=True, shell=False, timeout=10)

        # Log the command and its result (important for auditing)
        print(f"Executed command: {command}, Return code: {process.returncode}")
        print(f"Stdout: {process.stdout}")
        print(f"Stderr: {process.stderr}")


        if process.returncode == 0:
            return process.stdout, 200
        else:
            return f"Error: Command failed with return code {process.returncode}\n{process.stderr}", 500

    except FileNotFoundError:
        return "Error: Command not found", 404
    except subprocess.TimeoutExpired:
        return "Error: Command timed out", 504
    except Exception as e:
        print(f"An unexpected error occurred: {e}")  # Log the error
        return f"Error: An unexpected error occurred: {e}", 500


if __name__ == '__main__':
    # NEVER run this in production with debug=True.  It exposes sensitive information.
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=False, host='0.0.0.0', port=5000)

