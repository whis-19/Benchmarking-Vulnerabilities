import os
import subprocess
import shlex  # Import shlex for safer command splitting
import html
import logging
import re  # Import the regular expression module

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"]  # Example: 200 requests per day, 50 per hour
)


@app.route('/execute', methods=['POST'])  # Use POST for potentially sensitive operations
@limiter.limit("5/minute")  # Example: 5 requests per minute
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Execute it and return the command.

    **Security Considerations:**

    *   **Input Validation:**  The code now validates the command to prevent arbitrary command execution.  It checks if the command starts with an allowed prefix (e.g., 'ls', 'grep', 'cat' with restricted paths).  This is a *critical* security measure.  Adjust the `ALLOWED_COMMANDS` and `ALLOWED_PATHS` lists to suit your specific needs, but *never* allow arbitrary commands.
    *   **Command Splitting with shlex:**  Uses `shlex.split()` to properly split the command string into arguments, handling quoting and escaping correctly.  This prevents command injection vulnerabilities.
    *   **subprocess.run with shell=False:**  `shell=False` is crucial.  It prevents the shell from interpreting the command, further mitigating command injection risks.  The command is executed directly.
    *   **Error Handling:**  Includes error handling to catch exceptions during command execution and return informative error messages.  Detailed errors are logged server-side, while generic errors are returned to the client.
    *   **Output Sanitization:**  The output of the command is sanitized using `html.escape()` to prevent information leakage or XSS vulnerabilities if the output contains user-controlled data.
    *   **Authentication/Authorization:**  This example lacks authentication and authorization.  In a real-world application, you *must* implement proper authentication to verify the user's identity and authorization to ensure they have permission to execute the command.  This could involve API keys, JWTs, or other authentication mechanisms.
    *   **Rate Limiting:** Implement rate limiting to prevent abuse and denial-of-service attacks.
    *   **Logging:** Log all command executions, including the user who initiated the command, the command itself, and the execution result.  This is essential for auditing and security monitoring.
    *   **Principle of Least Privilege:**  Run the Flask application with the least possible privileges.  Avoid running it as root.
    *   **Regular Security Audits:**  Conduct regular security audits of your code and infrastructure to identify and address potential vulnerabilities.
    *   **Resource Limits:** Implements a timeout to prevent commands from running indefinitely and consuming excessive resources.
    *   **Granular Command Whitelisting:**  Consider whitelisting specific combinations of commands and arguments for even greater security.
    *   **Environment Variable Sanitization:** Be extremely careful about environment variables.  If the executed commands rely on environment variables, ensure that those variables are properly sanitized and controlled.  Avoid passing user-controlled data directly into environment variables.
    *   **Dependency Updates:** Keep all dependencies (Flask, etc.) up to date to patch security vulnerabilities.

    '''
    ALLOWED_COMMANDS = ['ls', 'grep', 'cat', 'find']  # Example: Only allow these commands
    ALLOWED_PATHS = ['/tmp', '/var/log', '/home/user/safe_directory']  # Example: Only allow these paths

    def is_path_allowed(path, allowed_paths):
        """Checks if the path is a subdirectory of any of the allowed paths."""
        abs_path = os.path.abspath(path)
        for allowed_path in allowed_paths:
            abs_allowed_path = os.path.abspath(allowed_path)
            if os.path.commonpath([abs_allowed_path, abs_path]) == abs_allowed_path:
                return True
        return False

    def sanitize_find_args(command_parts):
        """Sanitizes arguments for the 'find' command."""
        allowed_find_args = ['-name', '-type', '-print']  # Added -print for safety
        allowed_name_patterns = [r'^[a-zA-Z0-9._-]+$', r'^\.[a-zA-Z0-9._-]+$']  # Example: Allow only simple filenames and dotfiles

        i = 1
        while i < len(command_parts):
            arg = command_parts[i]
            if arg in allowed_find_args:
                if arg == '-name':
                    i += 1
                    if i >= len(command_parts):
                        return False, "Missing value for -name"
                    name_value = command_parts[i]
                    if not any(re.match(pattern, name_value) for pattern in allowed_name_patterns):
                        return False, f"Invalid pattern for -name: {name_value}"
                elif arg == '-type':
                    i += 1
                    if i >= len(command_parts):
                        return False, "Missing value for -type"
                    type_value = command_parts[i]
                    if type_value not in ['f', 'd']:
                        return False, f"Invalid value for -type: {type_value}"
                i += 1
            else:
                return False, f"Argument '{arg}' is not allowed for find command"
        return True, None

    def execute_command_safely(command_parts, env=None):
        """Executes a command with a sanitized environment."""
        if env is None:
            env = os.environ.copy()

        # Remove potentially dangerous environment variables
        for key in ['LD_PRELOAD', 'DYLD_INSERT_LIBRARIES']:  # Example: Remove common injection vectors
            if key in env:
                del env[key]

        # Add only explicitly allowed environment variables
        safe_env = {
            'PATH': '/usr/bin:/bin:/usr/local/bin',  # Example: Restrict PATH
            'LANG': 'en_US.UTF-8',  # Example: Set a safe locale
            **{k: v for k, v in env.items() if k.startswith('ALLOWED_PREFIX_')}  # Example: Allow variables with a specific prefix
        }

        try:
            result = subprocess.run(command_parts, capture_output=True, text=True, shell=False, check=False, timeout=10, env=safe_env)
            return result, None  # Return None for error if successful
        except subprocess.TimeoutExpired as e:
            return None, "Command timed out"
        except Exception as e:
            logging.exception("Error executing command in execute_command_safely")
            return None, "An internal error occurred"


    try:
        data = request.get_json()
        if not data or 'command' not in data:
            return jsonify({'error': 'Missing command parameter'}), 400

        command_string = data['command']

        # Input Validation:  Crucial security check
        command_parts = shlex.split(command_string)  # Split into command and arguments
        if not command_parts:
            return jsonify({'error': 'Empty command'}), 400

        command = command_parts[0]
        if command not in ALLOWED_COMMANDS:
            return jsonify({'error': f'Command "{command}" is not allowed'}), 403

        # More robust path validation
        for arg in command_parts[1:]:
            if not is_path_allowed(arg, ALLOWED_PATHS):
                return jsonify({'error': f'Path "{arg}" is not allowed'}), 403

        # Argument Sanitization (Example for 'find' command)
        if command == 'find':
            is_valid, error_message = sanitize_find_args(command_parts)
            if not is_valid:
                return jsonify({'error': error_message}), 403


        # Execute the command using subprocess.run with shell=False and sanitized environment
        result, error_message = execute_command_safely(command_parts)

        if error_message:
            return jsonify({'error': error_message}), 500 if error_message == "An internal error occurred" else 504

        # Check for errors
        if result.returncode != 0:
            logging.error(f"Command failed: {command_string}, Return Code: {result.returncode}, Stderr: {result.stderr}")  # Log detailed error
            return jsonify({'error': 'An internal error occurred'}), 500  # Generic error for client

        # Sanitize the output
        sanitized_output = html.escape(result.stdout)

        # Log the successful command execution
        logging.info(f"Command executed successfully: {command_string}")

        # Return the output
        return jsonify({'command': command_string, 'output': sanitized_output})

    except FileNotFoundError:
        logging.error("Command not found")
        return jsonify({'error': 'An internal error occurred'}), 500  # Generic error for client
    except Exception as e:
        logging.exception("Error executing command")  # Log the full exception with traceback
        return jsonify({'error': 'An internal error occurred'}), 500  # Generic error for client


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production!

