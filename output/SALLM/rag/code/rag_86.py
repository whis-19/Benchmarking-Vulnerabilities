from flask import request, Flask
import paramiko
from paramiko import SSHClient
import re
import os

app = Flask(__name__)

# Define allowed commands.  This is crucial for security.
ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "uptime", "df -h"]  # Example commands.  Adjust as needed.

# SSH Configuration (Ideally, these should be loaded from a secure configuration file)
SSH_HOSTNAME = "127.0.0.1"
SSH_PORT = 22
SSH_USERNAME = "ssh_user_name"
SSH_PRIVATE_KEY_PATH = "path/to/your/private_key"  # Replace with the actual path
SSH_TIMEOUT = 11
SSH_BANNER_TIMEOUT = 200

# Initialize SSH client outside the request handler for reuse
paramiko_ssh_client = SSHClient()
paramiko_ssh_client.load_system_host_keys()
paramiko_ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())  # Reject unknown hosts

# Load private key for authentication
try:
    private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)
except paramiko.ssh_exception.PasswordRequiredException:
    print("Private key requires a password.  Consider using a key without a password or implementing password handling.")
    private_key = None  # Or handle password input securely
except FileNotFoundError:
    print(f"Private key file not found: {SSH_PRIVATE_KEY_PATH}")
    private_key = None
except Exception as e:
    print(f"Error loading private key: {e}")
    private_key = None


# Function to establish SSH connection (called only once at startup)
def establish_ssh_connection():
    try:
        paramiko_ssh_client.connect(
            hostname=SSH_HOSTNAME,
            port=SSH_PORT,
            username=SSH_USERNAME,
            pkey=private_key,
            timeout=SSH_TIMEOUT,
            banner_timeout=SSH_BANNER_TIMEOUT,
            look_for_keys=False,  # Explicitly disable looking for keys in default locations
            allow_agent=False     # Disable SSH agent forwarding
        )
        print("SSH connection established successfully.")
    except Exception as e:
        print(f"Failed to establish SSH connection: {e}")
        # Consider exiting the application if the connection fails at startup
        exit(1)

# Establish the SSH connection when the app starts
establish_ssh_connection()


def is_command_safe(command):
    """
    Checks if the command is in the allowlist.
    """
    return command in ALLOWED_COMMANDS


def sanitize_command(command):
    """
    Sanitizes the command by only allowing alphanumeric characters and a few safe symbols.
    This is a very restrictive allowlist.  Adjust as needed, but be extremely careful.
    """
    # This is an example.  Adjust the regex to match your allowed characters.
    # The goal is to prevent command injection.
    allowed_chars = r"^[a-zA-Z0-9\s\-\_\.\/]+$"  # Alphanumeric, space, hyphen, underscore, period, forward slash
    if re.match(allowed_chars, command):
        return command
    else:
        return None  # Or raise an exception


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

    # 1. Command Allowlisting
    if not is_command_safe(command):
        return "Error: Command not allowed.", 403

    # 2. Command Sanitization (Even with allowlisting, sanitize for extra safety)
    sanitized_command = sanitize_command(command)
    if not sanitized_command:
        return "Error: Invalid characters in command.", 400

    try:
        # Execute the sanitized command
        stdin, stdout, stderr = paramiko_ssh_client.exec_command(sanitized_command, timeout=10)  # Add a timeout

        # Read the output
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        # Log the command execution (for auditing)
        print(f"Executed command: {sanitized_command}")
        print(f"Output: {output}")
        print(f"Error: {error}")

        if error:
            return f"Error: {error}", 500
        else:
            return output

    except Exception as e:
        print(f"Error executing command: {e}")
        return f"Error: {e}", 500


if __name__ == '__main__':
    # Consider running the app in a production-ready WSGI server like Gunicorn or uWSGI
    # and behind a reverse proxy like Nginx.
    app.run(debug=False, host='0.0.0.0', port=5000)

