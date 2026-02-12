from flask import request, Flask, jsonify
import paramiko
from paramiko import SSHClient
import re
import logging
import os  # For chmod
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.exceptions import HTTPException
import secrets
from flask import make_response

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration Variables
SECRET_KEY = secrets.token_hex(16)  # Generate a random secret key
app.config['SECRET_KEY'] = SECRET_KEY
# SSH Configuration
SSH_HOSTNAME = "127.0.0.1"
SSH_PORT = 22
SSH_USERNAME = "ssh_user_name"  # Replace with the actual username
SSH_PRIVATE_KEY_PATH = "/path/to/your/private/key"  # Replace with the actual path
SSH_KEY_PASSPHRASE = None  # Replace with passphrase if the key is encrypted

# Rate Limiting Configuration
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust as needed
)

# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Define a strict allowlist of allowed commands.  This is CRITICAL.
# Example: Allow 'df -h /path/to/mountpoint' instead of just 'df -h'
ALLOWED_COMMANDS = [
    "ls",
    "pwd",
    "whoami",
    "uptime",
    "df -h /",  # Example: Allow df -h only for the root filesystem
    "df -h /home", # Example: Allow df -h only for the /home filesystem
    "free -m" # Example: Allow free -m to check memory usage
]

# Initialize SSH client outside the request handler for reuse.
paramiko_ssh_client = SSHClient()
paramiko_ssh_client.load_system_host_keys()
paramiko_ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())  # Reject unknown hosts

# Attempt SSH connection at startup
try:
    # Load private key with passphrase handling
    if SSH_KEY_PASSPHRASE:
        private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH, password=SSH_KEY_PASSPHRASE)
    else:
        private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)

    paramiko_ssh_client.connect(
        hostname=SSH_HOSTNAME,
        port=SSH_PORT,
        username=SSH_USERNAME,
        pkey=private_key,
        timeout=11,
        banner_timeout=200
    )
    logging.info("SSH connection established successfully.")

except Exception as e:
    logging.error(f"SSH connection failed: {e}")
    # Handle the connection failure appropriately, e.g., log the error and exit.
    exit()


def is_command_safe(command):
    """
    Checks if the command is in the allowlist.  Also performs basic sanitization.
    """
    # Basic sanitization: Remove leading/trailing whitespace and multiple spaces.
    command = " ".join(command.strip().split())

    # Check if the command is in the allowlist.
    if command not in ALLOWED_COMMANDS:
        logging.warning(f"Command '{command}' not in allowlist.")
        return False

    return True


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = {
        "code": e.code,
        "name": e.name,
        "description": e.description,
    }
    response.content_type = "application/json"
    return response

@app.route('/external_exec_command')
@limiter.limit("5/minute")  # Rate limit this endpoint
def exec_command():
    """
    Get user command from the request using 'command'.
    Execute the command using paramiko ssh client.
    :return: stdout from the command
    """
    command = request.args.get('command')

    if not command:
        logging.warning("Missing 'command' parameter in request.")
        return jsonify({"error": "'command' parameter is missing."}), 400

    if not is_command_safe(command):
        logging.warning(f"Attempted to execute disallowed command: {command}")
        return jsonify({"error": "Command not allowed."}), 400

    try:
        # Execute the command using paramiko ssh client.
        stdin, stdout, stderr = paramiko_ssh_client.exec_command(command, timeout=10)  # Added timeout

        # Read the output.
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')

        if error:
            logging.error(f"Error executing command '{command}': {error}")
            return jsonify({"error": error}), 500

        logging.info(f"Executed command '{command}' successfully.")
        return jsonify({"output": output}), 200

    except Exception as e:
        logging.exception(f"Error executing command '{command}': {e}")  # Log the full exception
        return jsonify({"error": str(e)}), 500


def check_ssh_connection():
    """
    Checks if the SSH connection is active and reconnects if necessary.
    """
    try:
        transport = paramiko_ssh_client.get_transport()
        if transport is None or not transport.is_active():
            logging.warning("SSH connection is inactive. Reconnecting...")

            # Load private key with passphrase handling
            if SSH_KEY_PASSPHRASE:
                private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH, password=SSH_KEY_PASSPHRASE)
            else:
                private_key = paramiko.RSAKey.from_private_key_file(SSH_PRIVATE_KEY_PATH)

            paramiko_ssh_client.connect(
                hostname=SSH_HOSTNAME,
                port=SSH_PORT,
                username=SSH_USERNAME,
                pkey=private_key,
                timeout=11,
                banner_timeout=200
            )
            logging.info("SSH connection re-established.")
    except Exception as e:
        logging.error(f"Failed to reconnect to SSH server: {e}")


@app.before_request
def before_request():
    """
    Check SSH connection before each request.
    """
    check_ssh_connection()


if __name__ == '__main__':
    # Secure the private key file (example - adjust permissions as needed)
    try:
        os.chmod(SSH_PRIVATE_KEY_PATH, 0o600)  # Restrict access to the owner
        logging.info(f"Permissions set on SSH private key file: {SSH_PRIVATE_KEY_PATH}")
    except OSError as e:
        logging.warning(f"Failed to set permissions on SSH private key file: {e}")

    app.run(debug=True)

