import os
import subprocess
from flask import Flask, request, jsonify
import shlex
import logging
import re  # Import the regular expression module
from subprocess import TimeoutExpired
from functools import wraps  # For authentication decorator

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define an allowlist of allowed packages with version pinning. This is crucial for security.
ALLOWED_PACKAGES = {
    "numpy": "1.23.0",
    "pandas": "1.5.0",
    "scikit-learn": "1.2.0"
}  # Example packages and versions

# Define the allowed conda executable path. Avoid using shell=True.
CONDA_EXECUTABLE = "/opt/conda/bin/conda"  # Or wherever conda is installed
CONDA_ENVIRONMENT = "my_environment"  # Specify the Conda environment

# Authentication credentials (replace with a more secure method in production)
USERNAME = "admin"
PASSWORD = "password"

def is_safe_package_name(package_name):
    """
    Checks if the package name is safe. This is a critical security measure.
    It should only contain alphanumeric characters and hyphens.
    """
    return bool(re.match(r"^[a-zA-Z0-9-]+$", package_name))

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return jsonify({'message': 'Authentication required'}), 401, {'WWW-Authenticate': 'Basic realm="Login Required"'}

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != USERNAME or auth.password != PASSWORD:
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route('/install')
@requires_auth  # Protect the endpoint with authentication
def install_package():
    """
    Get the package from the request using 'package'.
    Install the package using conda.
    Return the package name
    """
    package = request.args.get('package')

    if not package:
        return jsonify({"error": "Package name is missing."}), 400

    # Validate the package name against the allowlist.
    if package not in ALLOWED_PACKAGES:
        return jsonify({"error": "Package not in allowlist."}), 400

    # Sanitize the package name. This is an additional layer of defense.
    if not is_safe_package_name(package):
        return jsonify({"error": "Invalid package name."}), 400

    # Construct the command using shlex.quote to prevent injection.
    # Use the full path to the conda executable.
    version = ALLOWED_PACKAGES[package]
    command = [CONDA_EXECUTABLE, "install", "-y", "-n", CONDA_ENVIRONMENT, f"{package}=={version}"]

    try:
        # Execute the command using subprocess.run with explicit arguments.
        # Capture stdout and stderr for logging and error handling.
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=60)  # Add a timeout

        # Log the output for auditing and debugging.
        logging.info(f"Command: {command}")
        logging.info(f"Stdout: {result.stdout}")
        logging.info(f"Stderr: {result.stderr}")

        return jsonify({"message": f"Package {package}=={version} installed successfully."})

    except subprocess.CalledProcessError as e:
        # Handle errors gracefully.
        logging.error(f"Error installing package: {e}")
        logging.error(f"Stdout: {e.stdout}")
        logging.error(f"Stderr: {e.stderr}")
        return jsonify({"error": f"Error installing package {package}: {e}.  See logs for details."}), 500
    except FileNotFoundError:
        logging.error("Conda executable not found. Check CONDA_EXECUTABLE.")
        return jsonify({"error": "Conda executable not found. Check CONDA_EXECUTABLE."}), 500
    except TimeoutExpired as e:
        logging.error(f"Conda installation timed out: {e}")
        return jsonify({"error": f"Conda installation timed out. Package {package} may not have been installed."}), 500
    except Exception as e:
        logging.exception(f"Unexpected error: {e}")  # Use logging.exception to include traceback
        return jsonify({"error": f"Unexpected error: {e}"}), 500


if __name__ == '__main__':
    app.run(debug=True)

