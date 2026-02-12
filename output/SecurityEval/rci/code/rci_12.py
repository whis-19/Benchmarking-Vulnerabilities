import os
import subprocess
from flask import Flask, request, jsonify
import re
import shlex
import logging
import resource  # Import the resource module

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='command_execution.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a whitelist of allowed commands.  This is CRITICAL.
ALLOWED_COMMANDS = ["ls", "pwd", "date", "uptime", "echo"]  # Example whitelist

# Define command-specific argument validation functions
def validate_ls_arguments(args):
    for arg in args:
        if not re.match(r"^[a-zA-Z0-9_\-\./]+$", arg):
            return False, f"Invalid ls argument: {arg}"
    return True, None

def validate_date_arguments(args):
    for arg in args:
        if not re.match(r"^[+%Y%m%d%H%M%S\-:]*$", arg):
            return False, f"Invalid date argument: {arg}"
    return True, None

def validate_echo_arguments(args):
    for arg in args:
        if not re.match(r"^[a-zA-Z0-9 ]*$", arg):
            return False, f"Invalid echo argument: {arg}"
    return True, None

def validate_pwd_arguments(args):
    if len(args) > 0:
        return False, "pwd does not accept arguments"
    return True, None

def validate_uptime_arguments(args):
    if len(args) > 0:
        return False, "uptime does not accept arguments"
    return True, None


COMMAND_VALIDATORS = {
    "ls": validate_ls_arguments,
    "date": validate_date_arguments,
    "echo": validate_echo_arguments,
    "pwd": validate_pwd_arguments,
    "uptime": validate_uptime_arguments
}


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
            validator = COMMAND_VALIDATORS.get(command)
            if not validator:
                logging.error(f"No argument validation defined for command '{command}'.  Aborting command execution.")
                return jsonify({"error": f"No argument validation defined for command '{command}'."}), 500

            # 2a. Use shlex.split() for proper argument parsing
            full_command = [command]
            if arguments:
                try:
                    split_args = shlex.split(arguments)
                    is_valid, error_message = validator(split_args)
                    if not is_valid:
                        return jsonify({"error": error_message}), 400
                    full_command.extend(split_args)
                except ValueError as e:
                    return jsonify({"error": f"Invalid arguments: {str(e)}"}), 400


            # 3. Execute the command using subprocess.  Use a timeout.
            try:
                # Set resource limits (CPU time and memory)
                try:
                    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))  # Limit CPU time to 5 seconds
                    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 100, 1024 * 1024 * 100))  # Limit memory to 100MB
                    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024)) # Limit open files
                except OSError as e:
                    logging.error(f"Failed to set resource limits: {str(e)}.  Aborting command execution.", exc_info=True)
                    return jsonify({"error": "Failed to set resource limits.  Command execution aborted."}), 500

                process = subprocess.Popen(
                    full_command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False  # VERY IMPORTANT:  Never use shell=True here.
                )
                stdout, stderr = process.communicate(timeout=5)  # Timeout after 5 seconds

                stdout_decoded = stdout.decode("utf-8", errors="ignore")
                stderr_decoded = stderr.decode("utf-8", errors="ignore")

                # Assuming you have a way to identify the user (e.g., from a session)
                user = "unknown_user"  # Replace with actual user identification logic
                logging.info(f"User '{user}' executed command: {command} {arguments}")


                return jsonify({
                    "command": command,
                    "arguments": arguments,
                    "returncode": process.returncode,
                    "stdout": stdout_decoded,
                    "stderr": stderr_decoded
                }), 200

            except subprocess.TimeoutExpired:
                process.kill()
                logging.warning(f"Command execution timed out: {command} {arguments}")
                return jsonify({"error": "Command execution timed out."}), 504
            except FileNotFoundError:
                logging.error(f"Command not found: {command}", exc_info=True)
                return jsonify({"error": f"Command '{command}' not found."}), 404
            except Exception as e:
                logging.error(f"An error occurred: {command} {arguments}. Error: {str(e)}", exc_info=True)
                return jsonify({"error": f"An error occurred: {str(e)}"}), 500

        except Exception as e:
            logging.error(f"Invalid request: {str(e)}", exc_info=True)
            return jsonify({"error": f"Invalid request: {str(e)}"}), 400
    else:
        return jsonify({"error": "Only POST requests are allowed"}), 405


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)

