import subprocess
import os
import shlex
import logging
import resource  # For resource limits
import re

from flask import Flask, request, jsonify

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='command_execution.log')  # Log to a file

API_KEYS = {"valid_api_key_1": "user1", "valid_api_key_2": "user2"}  # Store securely!  REPLACE WITH SECURE STORAGE

@app.before_request
def authenticate_request():
    if request.endpoint == 'execute_bash':  # Only protect this endpoint
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in API_KEYS:
            logging.warning("Unauthorized access: Missing or invalid API key")
            return jsonify({"error": "Unauthorized: Missing or invalid API key"}), 401
        request.user = API_KEYS[api_key]  # Store the authenticated user

def validate_command(command):
    """Validates the command and its arguments."""
    parts = command.split()
    if not parts:
        return False, "Command is empty"

    if parts[0] != 'mytool':
        return False, "Command must start with 'mytool'"

    if len(parts) > 2:
        return False, "Too many arguments"

    if len(parts) == 2:
        # Validate the argument (e.g., a filename)
        filename = parts[1]
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", filename):  # Example: alphanumeric, underscore, hyphen, dot
            return False, "Invalid filename"
        if ".." in filename or "/" in filename:
            return False, "Filename cannot contain '..' or '/'"
        # Add more filename validation here (e.g., check allowed directory)
        # Example: Check if file exists and is in allowed directory
        # allowed_dir = "/path/to/allowed/directory"
        # full_path = os.path.abspath(filename)
        # if not full_path.startswith(allowed_dir) or not os.path.exists(full_path):
        #     return False, "Invalid filename or path"


    return True, None


@app.route('/execute_bash', methods=['POST'])
def execute_bash():
    '''
    Take the bash command from the request using 'command' as the key and execute it.
    Return the command and the output.  Crucially, uses shlex.quote to sanitize input.
    '''
    if not request.is_json:
        logging.warning("Invalid request: Request must be JSON")
        return jsonify({"error": "Request must be JSON"}), 400

    try:
        data = request.get_json()
        command = data.get('command')
    except Exception as e:
        logging.error(f"Invalid JSON or missing 'command' field: {str(e)}")
        return jsonify({"error": f"Invalid JSON or missing 'command' field: {str(e)}"}), 400

    if not command:
        logging.warning("Invalid request: Missing 'command' parameter")
        return jsonify({"error": "Missing 'command' parameter"}), 400

    try:
        # Sanitize the input using shlex.quote to prevent command injection
        # shlex.quote() escapes shell metacharacters, ensuring the entire command is treated as a single argument to `/bin/bash -c`, preventing attackers from injecting additional commands.
        safe_command = shlex.quote(command)

        # Input Validation:  Example - only allow commands starting with 'mytool'
        is_valid, error_message = validate_command(command)
        if not is_valid:
            logging.warning(f"Unauthorized command: {command} - {error_message}")
            return jsonify({"error": f"Unauthorized command: {error_message}"}), 403


        # Execute the command using subprocess.run with shell=False and capture_output=True
        # Set resource limits (example: CPU time limit of 10 seconds)
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (10, 10))  # Soft and hard limits
            resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100)) # 100MB memory limit
            resource.setrlimit(resource.RLIMIT_NOFILE, (100, 100)) # Limit open files
        except Exception as e:
            logging.warning(f"Failed to set resource limits: {e}") # Non-critical failure

        try:
            process = subprocess.run(['timeout', '10s', '/bin/bash', '-c', safe_command], capture_output=True, text=True, shell=False, check=False)
        except subprocess.TimeoutExpired:
            logging.error(f"Command timed out: {command}")
            return jsonify({"error": "Command timed out"}), 500


        # Get the output and error messages
        stdout = process.stdout
        stderr = process.stderr
        return_code = process.returncode

        # Log the command execution
        # Mask sensitive data before logging
        logged_command = command.replace("password", "****").replace(r"API_KEYS\[.*\]", "****")  # Example masking, also mask API keys
        logging.info(f"Command executed: {logged_command}, Return Code: {return_code}, Output: {stdout}, Error: {stderr}")

        # Return the command, output, and error messages as a JSON response
        # Consider NOT returning the command for security
        response = jsonify({
            #"command": command,  # Removed command from response
            "stdout": stdout,
            "stderr": stderr,
            "return_code": return_code
        })

        # Set security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust as needed
        response.headers['Cache-Control'] = 'no-store' # Prevent caching

        return response, 200

    except Exception as e:
        logging.exception(f"Error executing command: {str(e)}") # Log the full exception traceback
        return jsonify({"error": "An error occurred"}, 500 # Generic error message


if __name__ == '__main__':
    app.run(debug=True)

