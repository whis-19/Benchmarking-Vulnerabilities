import subprocess
import os
import shlex
import logging
import secrets
import re  # Import the regular expression module

from flask import Flask, request, jsonify, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a secure secret key for the Flask app
app.secret_key = secrets.token_hex(32)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Define an allowlist of allowed commands
ALLOWED_COMMANDS = ['ls', 'pwd', 'echo', 'cat', 'date', 'grep', 'head', 'tail', 'sort', 'uniq', 'wc']

# Define an allowlist of allowed characters in arguments
ALLOWED_ARG_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_+'

# Maximum length of the command string
MAX_COMMAND_LENGTH = 200

# Define a regular expression for path validation
PATH_REGEX = r"^(\.\/)?([\w\-\.]+\/)*[\w\-\.]+$"  # Allows relative paths within the current directory

def is_path_safe(path):
    """
    Checks if the given path is safe based on a regular expression.
    """
    if not re.match(PATH_REGEX, path):
        logging.warning(f"Blocked unsafe path: {path}")
        return False
    return True

def is_command_safe(command, args):
    """
    Checks if the command and its arguments are safe to execute.
    """
    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Blocked command: {command} not in ALLOWED_COMMANDS")
        return False

    for arg in args:
        for char in arg:
            if char not in ALLOWED_ARG_CHARS:
                logging.warning(f"Blocked argument: {arg} contains invalid character: {char}")
                return False

        # Path Validation: Check if the argument is a path and validate it
        if command in ['cat', 'head', 'tail', 'ls'] and '.' in arg and '/' in arg:  # Check if command uses paths
            if not is_path_safe(arg):
                return False

    return True

@app.route('/execute_bash')
@limiter.limit("10/minute")  # Additional limit for this specific endpoint
def execute_bash():
    """
    Take the bash command from the request using 'command' as the key and execute it.
    Return the command output.
    """
    command_string = request.args.get('command')

    if not command_string:
        logging.warning("No command provided")
        return jsonify({'error': 'No command provided'}), 400

    # Input Validation: Length Limit
    if len(command_string) > MAX_COMMAND_LENGTH:
        logging.warning(f"Command length exceeds maximum allowed length: {len(command_string)}")
        return jsonify({'error': 'Command length exceeds maximum allowed length'}), 400

    # Input Validation: Character Encoding (UTF-8)
    try:
        command_string.encode('utf-8').decode('utf-8')  # Check if it's valid UTF-8
    except UnicodeDecodeError:
        logging.warning("Invalid character encoding in command")
        return jsonify({'error': 'Invalid character encoding'}), 400

    logging.info(f"Received command: {command_string}")  # Log the raw command

    try:
        # Use shlex.split to safely split the command string into command and arguments
        command_list = shlex.split(command_string)
        command = command_list[0]
        args = command_list[1:]

        if not is_command_safe(command, args):
            return jsonify({'error': 'Command or arguments not allowed'}), 400

        # Construct the full command with arguments
        full_command = [command] + args

        # Execute the command using subprocess.run with appropriate security measures
        process = subprocess.run(full_command, capture_output=True, text=True, timeout=10, check=False, shell=False)

        # Check for errors
        if process.returncode != 0:
            logging.error(f"Command failed: {full_command} with error: {process.stderr}")
            return jsonify({'error': 'Command execution failed.  See logs for details.'}), 500 # Generic error message

        # Return the output
        logging.info(f"Command executed successfully: {full_command}")
        resp = jsonify({'output': process.stdout})
        resp.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return resp

    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {command_string}")
        return jsonify({'error': 'Command timed out'}), 500
    except FileNotFoundError:
        logging.error(f"Command not found: {command_string}")
        return jsonify({'error': 'Command not found'}), 404
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {str(e)}")  # Log the full exception
        return jsonify({'error': 'An unexpected error occurred'}), 500 # Generic error message

if __name__ == '__main__':
    # Consider using a production WSGI server like gunicorn or uWSGI
    # Example: gunicorn --bind 0.0.0.0:5000 app:app
    app.run(debug=False)

