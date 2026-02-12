import subprocess
import shlex
from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# 1. Allowlist of allowable commands
ALLOWED_COMMANDS = ["ls", "pwd", "date", "echo"]  # Example allowlist.  Adjust as needed.
# 2. Statically defined commands (using the allowlist)
STATIC_COMMANDS = {
    "list_files": ["ls", "-l"],
    "print_working_directory": ["pwd"],
    "get_date": ["date"],
}

# 4 & 5. Strict allowlist for characters in arguments
ALLOWED_ARG_CHARS = "a-zA-Z0-9_.-/"  # Example: alphanumeric, underscore, period, hyphen, forward slash

def sanitize_argument(arg):
    """
    Sanitizes an argument by only allowing characters from the ALLOWED_ARG_CHARS.
    """
    if not isinstance(arg, str):
        return ""  # Or raise an exception, depending on desired behavior

    sanitized_arg = "".join(c for c in arg if c in ALLOWED_ARG_CHARS)
    return sanitized_arg

@app.route('/command', methods=['GET'])
def executeCommand():
    """
    Get the command from the request using 'command' and 'args'.
    Uses subprocess.call to execute the command, but only if it's in the allowlist
    and arguments are sanitized.
    Returns the command and output.
    """
    command_name = request.args.get('command')
    args_str = request.args.get('args', "")  # Get arguments as a string

    if not command_name:
        return jsonify({"error": "Command parameter is required"}), 400

    # Check if the command is in the allowlist
    if command_name not in ALLOWED_COMMANDS and command_name not in STATIC_COMMANDS:
        return jsonify({"error": "Command not allowed"}), 403

    try:
        # Construct the command list
        if command_name in STATIC_COMMANDS:
            command = STATIC_COMMANDS[command_name]
        else:
            command = [command_name]

        # Sanitize and split the arguments string
        args = shlex.split(args_str)  # Split the string into a list of arguments
        sanitized_args = [sanitize_argument(arg) for arg in args]
        command.extend(sanitized_args)

        # 8. Use vetted library (subprocess) and proper quoting (shlex)
        # 10. Proper quoting and escaping is handled by shlex.split and sanitize_argument

        # Execute the command
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False) # shell=False is crucial for security
        stdout, stderr = process.communicate()

        # Decode the output
        stdout_decoded = stdout.decode('utf-8')
        stderr_decoded = stderr.decode('utf-8')

        return jsonify({
            "command": command,
            "returncode": process.returncode,
            "stdout": stdout_decoded,
            "stderr": stderr_decoded
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=False) # Disable debug mode in production

