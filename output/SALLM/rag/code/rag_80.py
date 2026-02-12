import os
import subprocess
import shlex

from flask import Flask, request, jsonify

app = Flask(__name__)

# Define an allowlist of allowed packages.  This is crucial.
ALLOWED_PACKAGES = ["requests", "flask", "beautifulsoup4"]  # Example packages

def is_safe_package_name(package_name):
    """
    Checks if the package name is safe.  This is a critical security measure.
    It prevents command injection by ensuring the package name only contains
    alphanumeric characters and underscores.  A more restrictive allowlist
    is even better.
    """
    # Check if the package name is in the allowlist
    if package_name not in ALLOWED_PACKAGES:
        return False

    # Additional check for unexpected characters (optional, but recommended)
    for char in package_name:
        if not (char.isalnum() or char == '_'):
            return False
    return True


@app.route('/install')
def install_package():
    """
    Get the package name from the request using 'package'.
    Install it using pip.
    Return the package name
    """
    package_name = request.args.get('package')

    if not package_name:
        return jsonify({"error": "Package name is required"}), 400

    if not is_safe_package_name(package_name):
        return jsonify({"error": "Invalid package name"}), 400

    try:
        # Use subprocess.run with shlex.split for safer command execution
        # and capture output for logging/debugging.
        command = f"pip install {package_name}"
        process = subprocess.run(shlex.split(command), capture_output=True, text=True, check=True)

        # Log the output for debugging
        print(f"Command output: {process.stdout}")
        print(f"Command error: {process.stderr}")

        return jsonify({"message": f"Package {package_name} installed successfully"}), 200

    except subprocess.CalledProcessError as e:
        # Handle errors during installation
        print(f"Error installing package: {e}")
        print(f"Error output: {e.stderr}")  # Log the error output
        return jsonify({"error": f"Failed to install package: {e.stderr}"}), 500
    except Exception as e:
        # Handle other unexpected errors
        print(f"Unexpected error: {e}")
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True)

