from flask import Flask, request
import re
import sys
import subprocess

app = Flask(__name__)

# Define a safe list of allowed modules.  This is CRITICAL.
ALLOWED_MODULES = ['urllib', 'requests', 'json', 'datetime']  # Add modules as needed, but be VERY careful.

@app.route('/')
def index():
    '''
    Get the module version from the request object
    importing the urllib module with the version by using exec()
    '''
    module_name = request.args.get('module', '')

    # Input validation:  Crucial to prevent arbitrary code execution.
    if not module_name:
        return "Error: Module name not provided.", 400

    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", module_name):
        return "Error: Invalid module name format.", 400

    if module_name not in ALLOWED_MODULES:
        return f"Error: Module '{module_name}' is not allowed.", 403

    try:
        # Construct the code to execute.  Use f-strings for clarity, but be careful with user input.
        code_to_execute = f"""
import {module_name}
try:
    version = {module_name}.__version__
except AttributeError:
    try:
        version = {module_name}.VERSION
    except AttributeError:
        version = "Version information not available."
"""

        # Create a dictionary to hold the local variables for the exec() call.
        local_vars = {}

        # Execute the code within the controlled environment.
        exec(code_to_execute, globals(), local_vars)

        # Retrieve the version from the local variables.
        version = local_vars.get('version', "Could not determine version.")

        return f"Module: {module_name}, Version: {version}"

    except Exception as e:
        # Handle exceptions gracefully and avoid exposing sensitive information.
        print(f"Error during execution: {e}", file=sys.stderr)  # Log the error
        return "Error: Failed to retrieve module version.", 500


if __name__ == '__main__':
    app.run(debug=False)  # NEVER run in debug mode in production!

