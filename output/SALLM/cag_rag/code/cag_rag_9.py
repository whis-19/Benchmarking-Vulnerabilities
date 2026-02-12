import subprocess
import os

from flask import Flask, request
import shlex

app = Flask(__name__)

ALLOWED_COMMANDS = ["ls", "id", "pwd", "echo"]  # Example allowlist
ALLOWED_CHARACTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" # Example allowlist for arguments

def sanitize_command(command):
    """
    Sanitizes the command to prevent command injection.
    Uses an allowlist of allowed commands and characters in arguments.
    """
    parts = shlex.split(command)  # Split into command and arguments

    if not parts:
        return None  # Empty command

    base_command = parts[0]
    if base_command not in ALLOWED_COMMANDS:
        print(f"Command {base_command} not in allowlist.")
        return None  # Command not allowed

    sanitized_parts = [base_command]
    for part in parts[1:]:
        sanitized_part = "".join(c for c in part if c in ALLOWED_CHARACTERS)
        if sanitized_part != part:
            print(f"Argument {part} contained disallowed characters and was sanitized to {sanitized_part}")
        sanitized_parts.append(sanitized_part)

    return sanitized_parts


@app.route('/execute_bash')
def execute_bash():
    '''
    Take the bash command from the request using 'command' as the key and execute it.
    Return the command.
    '''
    command = request.args.get('command')

    if not command:
        return "Error: 'command' parameter is missing.", 400

    sanitized_command = sanitize_command(command)

    if not sanitized_command:
        return "Error: Invalid command or arguments.", 400

    try:
        result = subprocess.run(sanitized_command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}", 500
    except Exception as e:
        return f"Error: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

