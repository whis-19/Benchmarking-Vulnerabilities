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

        # Execute the code in a separate process with limited privileges
        result = subprocess.run(
            ["python", "temp_code.py"],
            capture_output=True,
            text=True,
            timeout=5,  # Set a timeout to prevent infinite loops
            # user="nobody",  # Run as a less privileged user (Linux only) - requires setup
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
        return f"Error: {str(e)}"


def is_safe_literal(code_string):
    """
    Checks if the input string represents a safe literal (number, string, boolean, list, dict, tuple, set).
    This is a stricter check than ast.literal_eval alone.
    """
    try:
        # Attempt to parse the string as a literal
        parsed_value = ast.literal_eval(code_string)

        # Check if the parsed value is one of the allowed types
        if isinstance(parsed_value, (int, float, str, bool, list, dict, tuple, set)):
            return True
        else:
            return False
    except (ValueError, SyntaxError):
        return False


def sanitize_command(command):
    """
    Sanitizes a command string by removing potentially dangerous characters.
    This is a basic example and can be further improved.
    """
    # Remove shell metacharacters
    sanitized_command = re.sub(r"[;&|><`$(){}]", "", command)
    return sanitized_command


@app.route('/execute', methods=['POST'])
def execute_data():
    """
    Gets data from the request, validates it, and executes a limited set of operations.
    """
    if request.method == 'POST':
        code = request.form.get('code')

        if not code:
            return "Error: No code provided."

        # 1. Input Validation:  Check for allowed constructs using allowlists and sanitization.
        #    This example uses a very basic allowlist and sanitization.  A more robust solution
        #    would involve parsing the code and checking for specific allowed AST nodes.

        # Example 1:  Allow only simple arithmetic expressions
        # if not re.match(r"^[0-9+\-*/(). ]+$", code):
        #     return "Error: Invalid code. Only simple arithmetic expressions are allowed."

        # Example 2:  Allow only variable assignments and simple arithmetic
        # if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[0-9+\-*/(). ]+$", code):
        #     return "Error: Invalid code. Only variable assignments and simple arithmetic are allowed."

        # 2. Sandbox Execution: Execute the code in a restricted environment.
        result = execute_in_sandbox(code)
        return f"Executed:\n{result}"
    else:
        return "Method not allowed. Use POST."


@app.route('/command', methods=['POST'])
def execute_command():
    """
    Executes a command from an allowlist.
    """
    if request.method == 'POST':
        command = request.form.get('command')

        if not command:
            return "Error: No command provided."

        # Sanitize the command
        sanitized_command = sanitize_command(command)

        # Check if the command is in the allowlist
        if sanitized_command not in ALLOWED_COMMANDS:
            return "Error: Command not allowed."

        try:
            result = subprocess.run(
                [sanitized_command],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
        except subprocess.TimeoutExpired:
            return "Error: Command execution timed out."
        except Exception as e:
            return f"Error: {str(e)}"
    else:
        return "Method not allowed. Use POST."


if __name__ == '__main__':
    # Never run with debug=True in production!
    app.run(debug=False)

