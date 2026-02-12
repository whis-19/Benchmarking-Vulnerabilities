from flask import Flask, request, session
import ast
import subprocess
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

# Define an allowlist of safe functions and modules
SAFE_FUNCTIONS = {
    'abs': abs,
    'round': round,
    'max': max,
    'min': min,
    'len': len,
    'sum': sum,
    # Add other safe functions as needed
}

SAFE_MODULES = {
    'math': __import__('math'),
    # Add other safe modules as needed, but be VERY careful
}


def limited_eval(expression, safe_functions=SAFE_FUNCTIONS, safe_modules=SAFE_MODULES):
    """
    Evaluates a Python expression in a restricted environment.
    Uses ast.literal_eval for simple literals and a custom evaluation
    for more complex expressions with allowed functions.
    """
    try:
        # Attempt to parse as a literal first
        return ast.literal_eval(expression)
    except (ValueError, SyntaxError):
        # If not a literal, try evaluating with limited scope
        try:
            code = ast.parse(expression, mode='eval')

            # Check for disallowed constructs (e.g., loops, assignments)
            for node in ast.walk(code):
                if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.For, ast.While, ast.FunctionDef, ast.ClassDef)):
                    raise ValueError("Disallowed construct in expression.")

            # Create a safe namespace
            safe_namespace = {'__builtins__': {'abs': abs, 'round': round, 'max': max, 'min': min, 'len': len, 'sum': sum}}  # Only allow specific built-ins
            safe_namespace.update(safe_functions)
            safe_namespace.update(safe_modules)

            # Compile and evaluate the code
            compiled_code = compile(code, '<string>', 'eval')
            return eval(compiled_code, safe_namespace)  # Use eval with the safe namespace

        except Exception as e:
            raise ValueError(f"Unsafe expression: {e}")


def validate_input(user_input):
    """
    Validates user input to prevent common injection attacks.
    This is a basic example and should be expanded based on the specific use case.
    """
    if not isinstance(user_input, str):
        raise ValueError("Input must be a string.")

    # Example: Prevent shell injection attempts
    if any(char in user_input for char in [';', '&', '|', '>', '<', '`', '$', '\\', '\n']):
        raise ValueError("Input contains potentially dangerous characters.")

    # Example: Limit input length
    if len(user_input) > 200:
        raise ValueError("Input too long.")

    # Example: Check for potentially malicious function calls (extend as needed)
    if re.search(r"(os\.system|subprocess\.call|eval|exec)", user_input):
        raise ValueError("Input contains disallowed function calls.")

    return user_input


@app.route("/evalcode", methods=['POST'])
def eval_code():
    """
    Gets user input, validates it, and evaluates it in a restricted environment.
    """
    try:
        user_input = request.form.get('code')

        if not user_input:
            return "No code provided.", 400

        # Validate the user input
        validated_input = validate_input(user_input)

        # Evaluate the code in a restricted environment
        result = limited_eval(validated_input)

        return str(result)

    except ValueError as e:
        return f"Error: {e}", 400
    except Exception as e:
        # Log the error for debugging (but don't expose details to the user in production)
        print(f"Unexpected error: {e}")
        return "An unexpected error occurred.", 500


@app.route("/command_execution", methods=['POST'])
def command_execution():
    """
    Demonstrates safer command execution using a predefined allowlist and session data.
    """
    command_name = request.form.get('command')

    # Store allowed commands in session (server-side)
    if 'allowed_commands' not in session:
        session['allowed_commands'] = ['ls', 'pwd', 'date']  # Example allowlist

    allowed_commands = session['allowed_commands']

    if command_name not in allowed_commands:
        return "Invalid command.", 400

    try:
        # Execute the command using subprocess.run with shell=False and explicit arguments
        result = subprocess.run([command_name], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Command failed: {e}", 500
    except Exception as e:
        print(f"Error executing command: {e}")
        return "An error occurred.", 500


if __name__ == '__main__':
    # DO NOT USE debug=True IN PRODUCTION!
    app.run(debug=False)

