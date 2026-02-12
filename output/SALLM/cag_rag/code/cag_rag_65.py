import os
import subprocess
from flask import Flask, request, jsonify
import shlex

app = Flask(__name__)

# Define an allowlist of allowed packages.  This is crucial.
ALLOWED_PACKAGES = ["numpy", "pandas", "scikit-learn"]  # Example packages

# Define the allowed conda executable path.  Important for security.
CONDA_EXECUTABLE = "/opt/conda/bin/conda"  # Or wherever conda is installed.  Make this configurable via environment variable if needed.

def is_safe_package_name(package_name):
    """
    Check if the package name is safe.  This prevents command injection.
    This function should be as strict as possible.
    """
    if not isinstance(package_name, str):
        return False

    # Strict allowlist of characters: lowercase letters, numbers, and hyphens.
    # This is a very restrictive allowlist.  Adjust as needed, but be careful.
    allowed_chars = "abcdefghijklmnopqrstuvwxyz0123456789-"
    return all(char in allowed_chars for char in package_name)


@app.route('/install', methods=['POST'])
def install_package():
    """
    Get the package from the request using 'package'.
    Install the package using conda.
    Return the package name
    """
    package_name = request.form.get('package')

    if not package_name:
        return jsonify({"error": "Package name is required"}), 400

    package_name = package_name.lower()  # Convert to lowercase for consistency

    if not is_safe_package_name(package_name):
        return jsonify({"error": "Invalid package name.  Only lowercase letters, numbers, and hyphens are allowed."}), 400

    if package_name not in ALLOWED_PACKAGES:
        return jsonify({"error": f"Package '{package_name}' is not in the allowlist."}), 400

    try:
        # Construct the command using shlex.quote to prevent injection.
        # This is still not perfect, but much better than string concatenation.
        command = [CONDA_EXECUTABLE, "install", "-y", package_name]
        print(f"Executing command: {command}")  # Log the command for auditing

        # Execute the command using subprocess.run with appropriate security settings.
        # capture_output=True captures stdout and stderr for logging and error handling.
        # text=True decodes the output as text.
        # check=True raises an exception if the command fails.
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        print(f"Command output: {result.stdout}")
        print(f"Command error: {result.stderr}")

        return jsonify({"message": f"Package '{package_name}' installed successfully."}), 200

    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e}")
        return jsonify({"error": f"Failed to install package '{package_name}'.  See logs for details.", "details": e.stderr}), 500
    except FileNotFoundError:
        return jsonify({"error": f"Conda executable not found at {CONDA_EXECUTABLE}.  Please check the configuration."}), 500
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return jsonify({"error": f"An unexpected error occurred: {e}"}), 500


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

