import subprocess
import os
import shlex
from flask import Flask, request, jsonify
import secrets
import hashlib
import ssl
import re
import logging
import string  # Import the string module

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

ALLOWED_COMMANDS = {
    "ls": {
        "args": ["-l", "-a", "-r", "-t", None],  # Allowed arguments, None means no argument
        "description": "List directory contents"
    },
    "pwd": {
        "args": [],
        "description": "Print working directory"
    },
    "whoami": {
        "args": [],
        "description": "Print current user"
    },
    "date": {
        "args": [],
        "description": "Print current date and time"
    },
    "echo": {
        "args": [None],  # Allow echo with no arguments
        "description": "Print a message"
    }
}

def sanitize_input(input_string):
    """
    Sanitizes the input string by removing non-printable characters.
    """
    return ''.join(filter(lambda x: x in string.printable, input_string))

def is_command_allowed(command_list):
    """
    Checks if the given command is in the allowlist and if the arguments are allowed.
    """
    command_name = command_list[0]
    if command_name not in ALLOWED_COMMANDS:
        return False

    allowed_args = ALLOWED_COMMANDS[command_name]["args"]

    # Check arguments
    for arg in command_list[1:]:
        if arg not in allowed_args:
            return False

    return True


@app.route('/execute_bash', methods=['POST'])
def execute_bash():
    """
    Takes the bash command from the request using 'command' as the key and executes it.
    Returns the command output.
    """
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    try:
        data = request.get_json()
        command = data.get('command')
    except Exception as e:
        return jsonify({"error": f"Invalid JSON or missing 'command' field: {str(e)}"}), 400

    if not command:
        return jsonify({"error": "Missing 'command' parameter"}), 400

    try:
        command_list = shlex.split(command)

        # Sanitize each element of the command list
        command_list = [sanitize_input(arg) for arg in command_list]

        if not is_command_allowed(command_list):
            return jsonify({"error": f"Command '{command}' is not allowed or contains invalid arguments."}), 403

        # Parameterized command execution
        result = subprocess.run(command_list, capture_output=True, text=True, check=True, timeout=10)

        return jsonify({"command": command, "output": result.stdout, "error": result.stderr, "returncode": result.returncode}), 200

    except subprocess.TimeoutExpired:
        logging.error(f"Command timed out: {command}")
        return jsonify({"error": "Command execution timed out."}), 504
    except subprocess.CalledProcessError as e:
        logging.error(f"Command execution failed: {command}, Error: {e}")
        return jsonify({"error": f"Command execution failed: {e}", "output": e.stdout, "stderr": e.stderr, "returncode": e.returncode}), 500
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {str(e)}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    if os.path.exists('cert.pem') and os.path.exists('key.pem'):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('cert.pem', 'key.pem')
        # Secure TLS configuration (example)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384')
        app.run(debug=False, ssl_context=context)  # Disable debug mode!
    else:
        print("Warning: cert.pem and key.pem not found.  Running in HTTP mode (not secure).")
        print("Generate a self-signed certificate for HTTPS (development only):")
        print("openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365")
        app.run(debug=False) # Disable debug mode!

