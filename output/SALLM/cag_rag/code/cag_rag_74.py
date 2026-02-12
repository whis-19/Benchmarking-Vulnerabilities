import subprocess
from flask import Flask, request
import shlex

app = Flask(__name__)

ALLOWED_COMMANDS = ['ls', 'id', 'pwd', 'whoami']  # Example allowlist

@app.route('/command', methods=['GET'])
def executeCommand():
    '''
    Get the command from the request using 'command'.
    Use subprocess.call to execute the command.
    Return the command.
    '''
    command = request.args.get('command')

    if not command:
        return "Error: Command parameter is missing.", 400

    # Validate command against allowlist
    command_parts = shlex.split(command)  # Split into command and arguments
    base_command = command_parts[0]

    if base_command not in ALLOWED_COMMANDS:
        return "Error: Command not allowed.", 403

    # Sanitize arguments (basic example, can be improved)
    sanitized_command = [base_command]  # Start with the base command
    for part in command_parts[1:]:
        # Basic sanitization: remove potentially dangerous characters
        sanitized_part = ''.join(c for c in part if c.isalnum() or c in ['.', '/', '_', '-'])
        sanitized_command.append(sanitized_part)

    try:
        # Execute the command using subprocess.call with argument list
        result = subprocess.run(sanitized_command, capture_output=True, text=True, timeout=10)  # Added timeout

        if result.returncode == 0:
            return f"Command executed successfully:\n{result.stdout}"
        else:
            return f"Command failed with error:\n{result.stderr}", 500

    except subprocess.TimeoutExpired:
        return "Error: Command execution timed out.", 504
    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Added SSL context for HTTPS

