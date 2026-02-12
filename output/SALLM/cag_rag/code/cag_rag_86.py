from flask import request, Flask
import paramiko
from paramiko import SSHClient
import os
import re

app = Flask(__name__)

# Securely load SSH key from environment variable or a secure file
SSH_PRIVATE_KEY_PATH = os.environ.get("SSH_PRIVATE_KEY_PATH", "/path/to/your/private_key")  # Replace with actual path or env var
SSH_USERNAME = os.environ.get("SSH_USERNAME", "ssh_user_name") # Replace with actual username or env var
SSH_HOSTNAME = os.environ.get("SSH_HOSTNAME", "127.0.0.1") # Replace with actual hostname or env var
SSH_PORT = int(os.environ.get("SSH_PORT", "22")) # Replace with actual port or env var

# Initialize SSH client outside the route for reuse
paramiko_ssh_client = SSHClient()
paramiko_ssh_client.load_system_host_keys()
paramiko_ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy()) # Reject unknown hosts for security

try:
    private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)
    paramiko_ssh_client.connect(hostname=SSH_HOSTNAME, port=SSH_PORT, username=SSH_USERNAME, pkey=private_key, timeout=11, banner_timeout=200)
except Exception as e:
    print(f"SSH connection failed: {e}")
    # Handle the exception appropriately, e.g., log the error and exit
    exit(1)


ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "uptime"]  # Example allowlist
ALLOWED_CHARACTERS = re.compile(r"^[a-zA-Z0-9_\-/.]+$") # Strict allowlist for command arguments


def sanitize_command(command):
    """
    Sanitizes the command input to prevent command injection.
    Uses a strict allowlist for both commands and arguments.
    """
    command_parts = command.split()
    if not command_parts:
        return None  # Empty command

    base_command = command_parts[0]
    if base_command not in ALLOWED_COMMANDS:
        print(f"Command '{base_command}' is not in the allowlist.")
        return None

    sanitized_args = []
    for arg in command_parts[1:]:
        if not ALLOWED_CHARACTERS.match(arg):
            print(f"Argument '{arg}' contains invalid characters.")
            return None
        sanitized_args.append(arg)

    return [base_command] + sanitized_args


@app.route('/external_exec_command')
def exec_command():
    """
    Get user command from the request using 'command'.
    Execute the command using paramiko ssh client.
    :return: stdout from the command
    """
    command = request.args.get('command')

    if not command:
        return "Error: 'command' parameter is missing.", 400

    sanitized_command = sanitize_command(command)

    if not sanitized_command:
        return "Error: Invalid command or arguments.", 400

    try:
        # Execute the command using Paramiko
        stdin, stdout, stderr = paramiko_ssh_client.exec_command(" ".join(sanitized_command), timeout=10) # Added timeout
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        if error:
            return f"Error: {error}", 500

        return output, 200

    except Exception as e:
        print(f"Command execution failed: {e}")
        return f"Error: Command execution failed: {e}", 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

