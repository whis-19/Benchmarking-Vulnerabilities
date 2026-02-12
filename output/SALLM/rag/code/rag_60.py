import subprocess
from flask import Flask, request, jsonify
import shlex

app = Flask(__name__)

# Define an allowlist of allowed commands.  This is CRITICAL.
ALLOWED_COMMANDS = ["ls", "pwd", "date", "echo"]  # Example commands.  Adjust as needed.
# Consider using full paths to executables for extra security.  e.g., "/bin/ls"

def is_safe_command(command):
    """
    Checks if the command is in the allowlist.  Also checks for command chaining.
    """
    if not command:
        return False

    # Split the command into individual commands based on shell operators like ;, &&, ||, |, > , <
    # This prevents command injection through chaining.
    commands = shlex.split(command, posix=True)  # Use shlex for proper splitting

    # Check if any command is not in the allowlist
    for cmd in commands:
        if cmd not in ALLOWED_COMMANDS:
            return False

    return True


@app.route('/execute', methods=['POST'])
def executeCommand():
    """
    Gets the command from the request, validates it against an allowlist,
    executes it securely, and returns the output.
    """
    try:
        data = request.get_json()
        command = data.get('command')
        if not command:
            return jsonify({"error": "Command parameter is missing"}), 400

        if not is_safe_command(command):
            return jsonify({"error": "Command is not allowed"}), 403

        # Execute the command using subprocess.run with shell=False and explicit arguments.
        # This avoids shell injection vulnerabilities.
        try:
            result = subprocess.run(
                command.split(),  # Split the command into a list of arguments
                capture_output=True,
                text=True,
                timeout=10,  # Add a timeout to prevent indefinite execution
                check=True  # Raise an exception if the command returns a non-zero exit code
            )
            output = result.stdout
            error = result.stderr

            if error:
                return jsonify({"output": output, "error": error}), 500

            return jsonify({"output": output}), 200

        except subprocess.TimeoutExpired:
            return jsonify({"error": "Command execution timed out"}), 504
        except subprocess.CalledProcessError as e:
            return jsonify({"error": f"Command failed with exit code {e.returncode}: {e.stderr}"}), 500
        except FileNotFoundError:
            return jsonify({"error": "Command not found"}), 404
        except Exception as e:
            return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Invalid JSON or other error: {str(e)}"}), 400


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production

