from flask import Flask, request, session
import ast
import subprocess
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

ALLOWED_COMMANDS = ["ls", "pwd", "date"]  # Example allowlist

def execute_in_sandbox(code):
    """
    Executes code in a restricted environment using subprocess.
    This is a basic example and can be further hardened.
    """
    try:
        # Create a temporary file to store the code
        with open("temp_code.py", "w") as f:
            f.write(code)

        # Execute the code in a subprocess with limited resources
        result = subprocess.run(
            ["python", "temp_code.py"],
            capture_output=True,
            timeout=5,  # Limit execution time
            # user="nobody",  # Run as a less privileged user (requires setup)
            # cwd="/tmp",  # Limit access to the filesystem
            text=True,
        )

        # Clean up the temporary file
        os.remove("temp_code.py")

        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: Code execution timed out."
    except Exception as e:
        return f"Error: {e}"


def is_safe_literal(code_string):
    """
    Checks if the code string contains only safe literals.
    This is a basic example and can be expanded.
    """
    try:
        ast.literal_eval(code_string)
        return True
    except (ValueError, SyntaxError):
        return False

def validate_command(command):
    """
    Validates if the command is in the allowlist.
    """
    command_name = command.split()[0]  # Get the base command
    return command_name in ALLOWED_COMMANDS

@app.route('/eval_code', methods=['POST'])
def eval_code():
    """
    Gets code from the request, validates it, executes it in a sandbox, and returns the result.
    """
    code = request.form.get('code')

    if not code:
        return "Error: No code provided."

    # 1. Input Validation: Check for potentially dangerous code patterns
    if re.search(r"import|os\.|subprocess\.|exec|eval|open|file", code):
        return "Error: Code contains potentially dangerous keywords."

    # 2. Allowlist-based validation (for simple expressions)
    if not is_safe_literal(code):
        # 3. Sandbox execution for more complex code (if needed)
        result = execute_in_sandbox(code)
        return result
    else:
        try:
            # Use ast.literal_eval for safe evaluation of literals
            result = ast.literal_eval(code)
            return str(result)
        except (ValueError, SyntaxError) as e:
            return f"Error: Invalid literal: {e}"

@app.route('/execute_command', methods=['POST'])
def execute_command():
    """
    Executes a command from the request, validating it against an allowlist.
    """
    command = request.form.get('command')

    if not command:
        return "Error: No command provided."

    # Validate the command against the allowlist
    if not validate_command(command):
        return "Error: Command not allowed."

    try:
        # Execute the command using subprocess.run
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Error: {e}"

@app.route('/store_data', methods=['POST'])
def store_data():
    """
    Stores data in the session.
    """
    data = request.form.get('data')

    if not data:
        return "Error: No data provided."

    session['stored_data'] = data
    return "Data stored in session."

@app.route('/retrieve_data')
def retrieve_data():
    """
    Retrieves data from the session.
    """
    if 'stored_data' in session:
        return session['stored_data']
    else:
        return "No data stored in session."

if __name__ == '__main__':
    app.run(debug=False)  # Disable debugging in production

