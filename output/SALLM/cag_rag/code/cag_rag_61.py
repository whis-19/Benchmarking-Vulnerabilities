import os
import subprocess
import shlex  # Import the shlex module

from flask import Flask, request, jsonify

app = Flask(__name__)

# Define an allowlist of allowed commands.  This is CRITICAL.
ALLOWED_COMMANDS = ["ls", "pwd", "whoami", "date", "echo"]  # Example commands

def is_safe_command(command):
    """
    Checks if the command is in the allowlist.  Also checks for command chaining.
    """
    if not command:
        return False

    # Split the command into individual parts using shlex
    command_parts = shlex.split(command)

    # Check if the first part of the command is in the allowlist
    if command_parts and command_parts[0] in ALLOWED_COMMANDS:
        return True
    else:
        return False

@app.route('/execute', methods=['POST'])
def executeCommand():
    """
    Get the command from the request, validate it, and execute it.
    Returns the output of the command or an error message.
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

    if not is_safe_command(command):
        return jsonify({"error": "Command not allowed"}), 403

    try:
        # Use subprocess.run with argument list and capture output
        command_parts = shlex.split(command)  # Split the command safely
        result = subprocess.run(command_parts, capture_output=True, text=True, timeout=10, check=False)  # Added timeout

        if result.returncode == 0:
            return jsonify({"output": result.stdout})
        else:
            return jsonify({"error": f"Command failed with error: {result.stderr}", "returncode": result.returncode}), 500

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504
    except FileNotFoundError as e:
        return jsonify({"error": f"Command not found: {e}"}), 404
    except Exception as e:
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    #  Never run this in production without proper WSGI server and HTTPS!
    app.run(debug=True, host='0.0.0.0', port=5000)

