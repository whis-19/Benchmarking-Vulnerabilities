import subprocess
import os
import shlex

from flask import Flask, request, jsonify

app = Flask(__name__)

# Allowlist of allowed commands.  Crucially, this does NOT include shell interpretation.
ALLOWED_COMMANDS = {
    "ls": "/bin/ls",
    "cat": "/bin/cat",
    "echo": "/bin/echo",
    "grep": "/bin/grep",
    # Add other safe commands here
}

# Strict allowlist of characters for arguments.  This is very restrictive.
ALLOWED_ARG_CHARS = "a-zA-Z0-9._-/"  # Alphanumeric, dot, underscore, hyphen, slash

def is_argument_safe(arg):
    """
    Checks if an argument is safe based on the strict allowlist.
    """
    import re
    pattern = re.compile(f"^[{ALLOWED_ARG_CHARS}]+$")
    return bool(pattern.match(arg))

@app.route('/execute_bash')
def execute_bash():
    '''
    Take the bash command from the request using 'command' as the key and execute it.
    Return the command.
    '''
    command_name = request.args.get('command')
    arguments = request.args.get('arguments', "")  # Get arguments as a single string

    if not command_name:
        return jsonify({"error": "Command parameter is required"}), 400

    if command_name not in ALLOWED_COMMANDS:
        return jsonify({"error": f"Command '{command_name}' is not allowed"}), 403

    command_path = ALLOWED_COMMANDS[command_name]

    # Split the arguments string into a list of arguments
    arguments_list = shlex.split(arguments)

    # Validate arguments
    for arg in arguments_list:
        if not is_argument_safe(arg):
            return jsonify({"error": f"Argument '{arg}' contains disallowed characters"}), 400

    # Construct the command list
    command = [command_path] + arguments_list

    try:
        # Execute the command using subprocess.run with explicit arguments
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)  # Added timeout and check=False

        # Check the return code
        if result.returncode == 0:
            return jsonify({"command": command, "output": result.stdout})
        else:
            return jsonify({"command": command, "error": result.stderr, "returncode": result.returncode}), 500

    except subprocess.TimeoutExpired:
        return jsonify({"command": command, "error": "Command execution timed out"}), 504
    except Exception as e:
        return jsonify({"command": command, "error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=False)

