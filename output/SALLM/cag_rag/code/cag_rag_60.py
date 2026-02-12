import subprocess
from flask import Flask, request
import shlex

app = Flask(__name__)

ALLOWED_COMMANDS = ['ping', 'traceroute', 'nslookup']  # Example allowlist

def is_safe_command(command):
    """
    Checks if the command is in the allowlist.
    """
    return command in ALLOWED_COMMANDS

@app.route('/execute')
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Execute it and return the command.
    '''
    command = request.args.get('command')

    if not command:
        return "Error: Command parameter is missing.", 400

    if not is_safe_command(command):
        return "Error: Command not allowed.", 403

    target = request.args.get('target')

    if not target:
        return "Error: Target parameter is missing.", 400

    # Basic input validation for target (example: hostname or IP address)
    #  More robust validation is highly recommended, e.g., using regex.
    if not (isinstance(target, str) and 0 < len(target) < 256):
        return "Error: Invalid target.", 400

    try:
        # Use shlex.split to properly split the command and target into a list of arguments
        # This helps prevent command injection by handling spaces and special characters correctly.
        command_list = [command, target]

        # Execute the command using subprocess.run with argument list and capture output.
        # shell=False is crucial for security.
        process = subprocess.run(command_list, capture_output=True, text=True, timeout=10)

        # Check for errors
        if process.returncode != 0:
            return f"Error: Command failed with return code {process.returncode}.  Output: {process.stderr}", 500

        return f"Command executed successfully. Output: {process.stdout}", 200

    except subprocess.TimeoutExpired:
        return "Error: Command timed out.", 504
    except FileNotFoundError:
        return "Error: Command not found.", 404
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS.  'adhoc' is for testing only.  Use proper certificates in production.

