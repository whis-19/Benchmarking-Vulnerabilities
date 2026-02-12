import os
import subprocess
from flask import Flask, request, abort
import re

app = Flask(__name__)

# Allowed commands (allowlist)
ALLOWED_COMMANDS = ["ping", "traceroute", "host", "nslookup"]

# Allowed characters in command arguments (strict allowlist)
ALLOWED_ARG_CHARS = re.compile(r"^[a-zA-Z0-9\.\-]+$")  # letters, numbers, period, hyphen

# Allowed domains/IPs (allowlist)
ALLOWED_DOMAINS = ["example.com", "192.168.1.1", "8.8.8.8"]  # Replace with your allowed domains/IPs


def is_valid_domain(domain):
    """
    Validates a domain against the allowlist.
    """
    return domain in ALLOWED_DOMAINS


def sanitize_argument(arg):
    """
    Sanitizes a command argument by checking against a strict allowlist of characters.
    """
    if not ALLOWED_ARG_CHARS.match(arg):
        return None  # or raise an exception, depending on desired behavior
    return arg


@app.route("/command")
def executeCommand():
    """
    Receives a command from a GET request, validates it, and executes it.
    """
    command = request.args.get("cmd")
    target = request.args.get("target")

    if not command or not target:
        return "Error: 'cmd' and 'target' parameters are required.", 400

    # Validate command against allowlist
    if command not in ALLOWED_COMMANDS:
        return f"Error: Command '{command}' is not allowed.", 400

    # Validate target (domain/IP) against allowlist and sanitize
    if not is_valid_domain(target):
        return f"Error: Target '{target}' is not allowed.", 400

    sanitized_target = sanitize_argument(target)
    if not sanitized_target:
        return "Error: Invalid characters in target.", 400

    # Construct the command with argument list (avoiding shell=True)
    try:
        cmd = [command, sanitized_target]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable=f"/usr/bin/{command}") # Specify full path to executable
        stdout, stderr = process.communicate(timeout=10)  # Add a timeout to prevent hanging

        if process.returncode != 0:
            return f"Error: Command execution failed with code {process.returncode}.  Stderr: {stderr.decode()}", 500

        return stdout.decode()

    except FileNotFoundError:
        return f"Error: Command '{command}' not found.", 500
    except subprocess.TimeoutExpired:
        return "Error: Command execution timed out.", 500
    except Exception as e:
        return f"Error: An unexpected error occurred: {str(e)}", 500


if __name__ == "__main__":
    #  Never run this in production without proper WSGI server and HTTPS!
    #  This is just for local development.
    app.run(debug=True, host="0.0.0.0", port=5000)

