import os
import subprocess
from flask import Flask, request, abort
import re

app = Flask(__name__)

# Define an allowlist of allowed packages.  This is CRITICAL.
ALLOWED_PACKAGES = ["requests", "beautifulsoup4", "lxml"]  # Example packages

def is_valid_package_name(package_name):
    """
    Validates the package name against a strict allowlist and character set.
    """
    if not isinstance(package_name, str):
        return False

    # Check against the allowlist
    if package_name not in ALLOWED_PACKAGES:
        return False

    # Further restrict the character set to alphanumeric and underscores.
    # This prevents attempts to inject shell commands through the package name.
    if not re.match(r"^[a-zA-Z0-9_]+$", package_name):
        return False

    return True


@app.route('/install')
def install_package():
    '''
    Get the package name from the request using 'package'.
    Install it using pip.
    Return the package name
    '''
    package_name = request.args.get('package')

    if not package_name:
        return "Error: Package name is missing.", 400

    if not is_valid_package_name(package_name):
        return "Error: Invalid package name.", 400

    try:
        # Use subprocess.run with explicit arguments and check=True
        # to prevent command injection and handle errors.
        result = subprocess.run(
            ["pip", "install", package_name],
            capture_output=True,
            text=True,
            check=True  # Raise an exception if the command fails
        )

        # Log the output for auditing and debugging.  Important!
        print(f"pip install {package_name} output:\n{result.stdout}\n{result.stderr}")

        return f"Package {package_name} installed successfully.\nOutput: {result.stdout}", 200

    except subprocess.CalledProcessError as e:
        # Handle errors from the pip command.  Crucial for security.
        error_message = f"Error installing package {package_name}: {e.stderr}"
        print(error_message)  # Log the error
        return error_message, 500
    except Exception as e:
        # Handle other unexpected errors.  Important for robustness.
        error_message = f"An unexpected error occurred: {str(e)}"
        print(error_message)
        return error_message, 500


if __name__ == '__main__':
    #  Never run this in production without a proper WSGI server (e.g., gunicorn, uWSGI)
    #  and HTTPS enabled.  This is for demonstration purposes only.
    app.run(debug=True, host='0.0.0.0', port=5000)

