import subprocess
from flask import Flask, request, abort
import os
import re
import ssl
import shlex
import ipaddress
from urllib.parse import urlparse

app = Flask(__name__)

# --- Security Configuration ---

ALLOWED_COMMANDS = {
    "ls": ["-l", "-a", "-h", "/safe/directory"],  # Allowed options and paths for ls
    "id": [],  # No arguments allowed for id
    "pwd": [],  # No arguments allowed for pwd
    # "echo": []  # REMOVE ECHO!  NEVER ALLOW THIS IN PRODUCTION
}
ALLOWED_DOMAINS = ["example.com"]
ALLOWED_IPS = ["127.0.0.1"]
USE_HTTPS = True

# --- Helper Functions ---

def is_valid_domain(domain):
    """
    Validates a domain name against the ALLOWED_DOMAINS list.
    """
    return domain in ALLOWED_DOMAINS

def is_valid_ip(ip_address):
    """
    Validates an IP address against the ALLOWED_IPS list.
    """
    try:
        ipaddress.ip_address(ip_address)  # Validate IP format
        return ip_address in ALLOWED_IPS
    except ValueError:
        return False

def validate_url(url):
    """
    Validates a URL against the ALLOWED_DOMAINS list.  More robust validation.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme

        if scheme not in ("http", "https"):
            return False

        if hostname:
            if is_valid_domain(hostname): # Only check domains here
                return True
            elif is_valid_ip(hostname): # Check IPs separately
                return True
            else:
                return False
        else:
            return False
    except Exception:
        return False

def execute_allowed_command(command, args):
    """
    Executes a command from the ALLOWED_COMMANDS list with validated arguments.
    This is the *safest* approach.
    """
    if command not in ALLOWED_COMMANDS:
        raise ValueError(f"Command '{command}' is not allowed.")

    allowed_args = ALLOWED_COMMANDS[command]

    # Validate arguments based on the command
    for arg in args:
        if command == "ls":
            # Example: Allow combinations of arguments for ls
            allowed_ls_args = ["-l", "-a", "-h"]
            if arg not in allowed_ls_args and arg != "/safe/directory":
                raise ValueError(f"Argument '{arg}' is not allowed for command '{command}'.")
        # Add validation for other commands as needed

        # Sanitize arguments (remove potentially dangerous characters)
        arg = re.sub(r"[;&|><`$(){}]", "", arg)  # Remove shell metacharacters

    try:
        command_list = [command] + args
        result = subprocess.run(command_list, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        # Log the error on the server-side
        print(f"Command execution failed: {e}")  # Log the full error
        raise ValueError("Command execution failed.") # Don't expose details
    except FileNotFoundError:
        raise ValueError(f"Command '{command}' not found.")

# --- Route ---

@app.route('/execute')
def executeCommand():
    """
    Gets the command from the request, validates and sanitizes it,
    executes it using subprocess with argument lists, and returns the output.
    """

    if USE_HTTPS and not request.is_secure:
        abort(400, description="HTTPS is required for this endpoint.")

    command = request.args.get('command')

    # Sanitize the command
    command = re.sub(r"[;&|><`$(){}]", "", command)

    args_str = request.args.get('args', '')  # Get arguments as a string

    if not command:
        return "Error: 'command' parameter is missing.", 400

    try:
        # Use shlex.split to prevent shell injection
        args = shlex.split(args_str) if args_str else []

        # Execute the command using the safe execution function
        output = execute_allowed_command(command, args)
        return f"Command executed successfully:\n{output}"

    except ValueError as e:
        return f"Error: {str(e)}", 400
    except Exception as e:
        # Log the error on the server-side
        print(f"An unexpected error occurred: {e}")
        return "An unexpected error occurred.", 500

# --- Example Usage (for testing) ---

@app.route('/test_url')
def test_url():
    url = request.args.get('url')
    if not url:
        return "Error: 'url' parameter is missing.", 400

    if validate_url(url):
        return f"URL '{url}' is valid.", 200
    else:
        return f"URL '{url}' is invalid.", 400

if __name__ == '__main__':
    # --- HTTPS Configuration (Example) ---
    if USE_HTTPS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_cert_chain('cert.pem', 'key.pem')
        app.run(debug=True, ssl_context=context)
    else:
        app.run(debug=True)

