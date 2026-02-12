import subprocess
import shlex
from flask import Flask, request, jsonify
import os
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Define a whitelist of allowed commands with arguments.
# Use absolute paths for commands.
# Store allowed argument combinations as lists of lists.
ALLOWED_COMMANDS = {
    "/usr/bin/ls": [
        ["-l"],
        ["-a"],
        ["-h"],
        ["-t"],
        ["-r"],
        ["-S"],
        ["."],
        ["-l", "-a"],
        ["-l", "-h"],
        ["-a", "-h"],
        ["-l", "-a", "-h"]
    ],
    "/usr/bin/pwd": [[]],  # Allow pwd with no arguments
    "/usr/bin/date": [
        ["+%Y-%m-%d"],
        ["+%H:%M:%S"],
        ["+%Y-%m-%d", "+%H:%M:%S"],
        ["+%H:%M:%S", "+%Y-%m-%d"]
    ],
    "/usr/bin/uptime": [[]]  # Allow uptime with no arguments
}

# Define a safe path for execution (used only for PATH clearing).
SAFE_PATH = "/usr/bin"

# Define a regular expression to redact sensitive information from logs
SENSITIVE_DATA_REGEX = re.compile(r"(password|api_key)=\w+", re.IGNORECASE)


def validate_command(command_list):
    """
    Validates the command against the ALLOWED_COMMANDS whitelist.
    Returns True if the command is valid, False otherwise.
    """
    if not command_list:
        return False

    command_path = command_list[0]
    if command_path not in ALLOWED_COMMANDS:
        logging.warning(f"Command '{command_path}' not in ALLOWED_COMMANDS.")
        return False

    allowed_arg_combinations = ALLOWED_COMMANDS[command_path]
    provided_args = command_list[1:]

    if provided_args not in allowed_arg_combinations:
        logging.warning(f"Argument combination '{provided_args}' not allowed for command '{command_path}'.")
        return False

    # Additional input validation for arguments (example: filename)
    if command_path == "/usr/bin/ls":
        for arg in provided_args:
            if ".." in arg:
                logging.warning(f"Path traversal detected in argument: {arg}")
                return False
            if len(arg) > 100:  # Limit filename length
                logging.warning(f"Argument too long: {arg}")
                return False

    return True


@app.route('/command', methods=['GET'])
@limiter.limit("5/second")  # Rate limit to 5 requests per second
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Use subprocess.run to execute the command, but only if it's in the ALLOWED_COMMANDS list.
    Return the command and the output.
    '''
    command = request.args.get('command')

    if not command:
        logging.warning("Command parameter is missing.")
        return jsonify({"error": "Command parameter is missing"}), 400

    # Sanitize the command for logging (redact sensitive data)
    sanitized_command = SENSITIVE_DATA_REGEX.sub("[REDACTED]", command)

    try:
        # Security: Use shlex.split to prevent command injection.
        command_list = shlex.split(command)

        # Validate the command
        if not validate_command(command_list):
            logging.warning(f"Command '{sanitized_command}' is not allowed or contains invalid arguments.")
            return jsonify({"error": f"Command is not allowed or contains invalid arguments."}), 403

        # Security: Clear the PATH environment variable and set it to SAFE_PATH.
        env = {"PATH": SAFE_PATH}

        # Security: Use subprocess.run with explicit arguments and timeout.
        # capture_output=True captures both stdout and stderr.
        # text=True decodes the output as text.
        # timeout=5 sets a maximum execution time to prevent denial-of-service.
        result = subprocess.run(command_list, capture_output=True, text=True, timeout=5, check=False, env=env)  # check=False prevents exceptions on non-zero exit codes

        if result.returncode == 0:
            logging.info(f"Command '{sanitized_command}' executed successfully.")
            return jsonify({"command": command, "output": result.stdout})
        else:
            logging.error(f"Command '{sanitized_command}' failed with return code {result.returncode}")
            logging.debug(f"Stderr: {result.stderr}")  # Log stderr for debugging
            return jsonify({"error": "Command execution failed."}), 500  # Generic error message

    except subprocess.TimeoutExpired:
        logging.warning(f"Command '{sanitized_command}' timed out.")
        return jsonify({"error": "Command timed out"}), 504  # Return 504 Gateway Timeout
    except FileNotFoundError as e:
        logging.error(f"Command not found: {e}")
        return jsonify({"error": "Command not found"}), 404 # Return 404 Not Found
    except Exception as e:
        logging.exception(f"An unexpected error occurred while executing command '{sanitized_command}': {e}")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred"}), 500


def check_commands_exist(allowed_commands, safe_path):
    """
    Checks if all allowed commands exist in the SAFE_PATH.
    """
    for command in allowed_commands:
        full_path = os.path.join(safe_path, os.path.basename(command))
        if not os.path.exists(command):
            logging.error(f"Command '{command}' not found in '{safe_path}'.")
            return False
    return True


if __name__ == '__main__':
    if not check_commands_exist(ALLOWED_COMMANDS.keys(), SAFE_PATH):
        print("Error: Not all allowed commands exist in SAFE_PATH.  Exiting.")
        exit(1)

    # Example of using Flask-Talisman (install with pip install flask-talisman)
    # from flask_talisman import Talisman
    # talisman = Talisman(app, content_security_policy={
    #     'default-src': '\'self\'',
    #     'script-src': '\'self\'',
    #     'style-src': '\'self\'',
    #     'img-src': '*'
    # })

    app.run(debug=False)  # Disable debug mode in production!

