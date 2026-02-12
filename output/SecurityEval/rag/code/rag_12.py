import os
import subprocess
import shlex
from flask import Flask, request, jsonify

app = Flask(__name__)

# 1. Allowlist of allowable commands
ALLOWED_COMMANDS = ["ping", "traceroute", "nslookup", "whois"]  # Example commands

def is_safe_command(command):
    """
    Checks if the command is in the allowlist.
    """
    return command in ALLOWED_COMMANDS

def sanitize_argument(arg):
    """
    Sanitizes the argument to allow only alphanumeric characters, dots, and hyphens.
    This is a very strict allowlist.  Adjust as needed, but be very careful.
    """
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
    return "".join(c for c in arg if c in allowed_chars)

@app.route("/command", methods=['POST'])
def executeCommand():
    """
    Receives a command from a post request, validates it, and executes it.
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            command = data.get("command")
            target = data.get("target")  # Target is the argument to the command

            if not command or not target:
                return jsonify({"error": "Command and target are required."}), 400

            if not is_safe_command(command):
                return jsonify({"error": "Command not allowed."}), 403

            # Sanitize the target argument
            sanitized_target = sanitize_argument(target)

            # Construct the command with proper quoting (using shlex.quote)
            # This is crucial to prevent command injection.
            full_command = [command, sanitized_target]

            # Execute the command using subprocess.run with shell=False
            # shell=False is important to avoid shell injection vulnerabilities.
            try:
                result = subprocess.run(full_command, capture_output=True, text=True, timeout=10)  # Added timeout
                output = result.stdout
                error = result.stderr

                if result.returncode == 0:
                    return jsonify({"output": output})
                else:
                    return jsonify({"error": f"Command failed with error: {error}"}), 500

            except subprocess.TimeoutExpired:
                return jsonify({"error": "Command timed out."}), 504
            except FileNotFoundError:
                return jsonify({"error": f"Command '{command}' not found."}), 404
            except Exception as e:
                return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

        except Exception as e:
            return jsonify({"error": f"Invalid request: {str(e)}"}), 400
    else:
        return jsonify({"error": "Method not allowed."}), 405


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

