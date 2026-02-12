import os
import subprocess
import shlex
import re  # Import the regular expression module
import logging

from flask import Flask, request, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import yaml  # For loading ALLOWED_COMMANDS from a file

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# Load ALLOWED_COMMANDS from a YAML file
try:
    with open("allowed_commands.yaml", "r") as f:
        ALLOWED_COMMANDS = yaml.safe_load(f)
    logging.info("Loaded ALLOWED_COMMANDS from allowed_commands.yaml")
except FileNotFoundError:
    ALLOWED_COMMANDS = {}
    logging.warning("allowed_commands.yaml not found.  ALLOWED_COMMANDS is empty.")
except yaml.YAMLError as e:
    ALLOWED_COMMANDS = {}
    logging.error(f"Error loading allowed_commands.yaml: {e}. ALLOWED_COMMANDS is empty.")


def sanitize_echo_argument(arg):
    """
    Sanitizes the argument to the echo command to prevent code injection.
    This is an example and should be adapted to your specific needs.
    """
    # Example: Allow only alphanumeric characters and spaces
    sanitized_arg = re.sub(r"[^a-zA-Z0-9\s]", "", arg)
    return sanitized_arg

def is_command_safe(command):
    """
    Checks if the command is in the allowlist and validates arguments.
    Uses absolute paths and regular expressions for more robust validation.
    """
    command_parts = shlex.split(command)  # Split into command and arguments
    if not command_parts:
        return False  # Empty command

    base_command = os.path.abspath(command_parts[0])  # Resolve absolute path
    if base_command not in ALLOWED_COMMANDS:
        logging.warning(f"Command {base_command} not in ALLOWED_COMMANDS")
        return False

    allowed_args = ALLOWED_COMMANDS[base_command]

    # Handle echo command with specific sanitization
    if base_command == "/usr/bin/echo":
        if len(command_parts) > 1:
            # Sanitize the argument to echo
            original_arg = command_parts[1]
            sanitized_arg = sanitize_echo_argument(original_arg)
            if sanitized_arg != original_arg:
                logging.warning("echo argument was sanitized")  # Log this!
                command_parts[1] = sanitized_arg  # Replace with sanitized version
            # Check if the sanitized argument is empty after sanitization
            if not sanitized_arg:
                logging.warning("echo argument is empty after sanitization")
                return False
        # Allow echo with no arguments
        return True

    # Check if the number of arguments matches the allowed number
    if len(command_parts) - 1 != len(allowed_args):
        logging.warning(f"Incorrect number of arguments for {base_command}. Expected {len(allowed_args)}, got {len(command_parts) - 1}")
        return False

    # Validate arguments against the allowed arguments
    for i, arg in enumerate(command_parts[1:]):
        if arg != allowed_args[i]:
            logging.warning(f"Argument {arg} does not match allowed argument {allowed_args[i]} for {base_command}")
            return False

    return True


@app.route('/execute', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit to 5 requests per minute
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Execute it and return the output.
    '''
    if not request.is_json:
        logging.warning("Request is not JSON")
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    command = data.get('command')

    if not command:
        logging.warning("Missing 'command' parameter")
        return jsonify({"error": "Missing 'command' parameter"}), 400

    # 1. Check against allowlist
    if not is_command_safe(command):
        logging.warning(f"Command '{command}' is not allowed")
        return jsonify({"error": "Command not allowed"}), 403

    try:
        # 3. Use subprocess.run with shlex.split for safer execution
        #    shlex.split handles quoting and escaping better than naive string splitting.
        command_list = shlex.split(command)
        logging.info(f"Executing command: {command_list}")
        process = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=10)  # Added timeout

        # 9. Proper output encoding (already handled by text=True in subprocess.run)
        output = process.stdout
        error = process.stderr

        # Logging (basic example)
        logging.info(f"Executed command: {command}, Return code: {process.returncode}")

        return jsonify({"command": command, "output": output, "error": error, "returncode": process.returncode}), 200

    except subprocess.TimeoutExpired:
        logging.error("Command timed out")
        return jsonify({"error": "Command timed out"}), 504
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed with return code {e.returncode}: {e.stderr}")
        logging.exception(e) # Log the full exception
        return jsonify({"error": "Command execution failed"}), 500 # Generic error message
    except Exception as e:
        logging.exception(e) # Log the full exception
        return jsonify({"error": "An unexpected error occurred"}), 500 # Generic error message

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


if __name__ == '__main__':
    app.run(debug=False)

