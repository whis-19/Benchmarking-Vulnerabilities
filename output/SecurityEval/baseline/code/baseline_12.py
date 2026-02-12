import os
import subprocess
from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Define a whitelist of allowed commands.  This is CRITICAL.
ALLOWED_COMMANDS = ["ls", "pwd", "date", "uptime", "echo"]  # Example whitelist

# Define a regular expression to validate arguments.  Restrict characters.
ARGUMENT_REGEX = r"^[a-zA-Z0-9_\-\./ ]*$"  # Allow alphanumeric, underscore, hyphen, period, slash, and space.  Adjust as needed.

@app.route("/command", methods=['POST'])
def executeCommand():
    """
    Receives a command from a post request, validates it, and executes it.
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            command = data.get("command")
            arguments = data.get("arguments", "")  # Arguments are optional

            if not command:
                return jsonify({"error": "Command is required"}), 400

            # 1. Command Whitelisting:  Crucial security measure.
            if command not in ALLOWED_COMMANDS:
                return jsonify({"error": f"Command '{command}' is not allowed."}), 403

            # 2. Argument Validation:  Prevent command injection.
            if not re.match(ARGUMENT_REGEX, arguments):
                return jsonify({"error": "Invalid arguments.  Arguments contain disallowed characters."}), 400

            # 3. Construct the command safely.  Use subprocess.list2cmdline for proper quoting.
            full_command = [command]
            if arguments:
                full_command.extend(arguments.split())  # Split arguments into a list

            # 4. Execute the command using subprocess.  Use a timeout.
            try:
                process = subprocess.Popen(
                    full_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False  # VERY IMPORTANT:  Never use shell=True here.
                )
                stdout, stderr = process.communicate(timeout=5)  # Timeout after 5 seconds

                stdout_decoded = stdout.decode("utf-8", errors="ignore")
                stderr_decoded = stderr.decode("utf-8", errors="ignore")

                return jsonify({
                    "command": command,
                    "arguments": arguments,
                    "returncode": process.returncode,
                    "stdout": stdout_decoded,
                    "stderr": stderr_decoded
                }), 200

            except subprocess.TimeoutExpired:
                process.kill()
                return jsonify({"error": "Command execution timed out."}), 504
            except FileNotFoundError:
                return jsonify({"error": f"Command '{command}' not found."}), 404
            except Exception as e:
                return jsonify({"error": f"An error occurred: {str(e)}"}), 500

        except Exception as e:
            return jsonify({"error": f"Invalid request: {str(e)}"}), 400
    else:
        return jsonify({"error": "Only POST requests are allowed"}), 405


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

