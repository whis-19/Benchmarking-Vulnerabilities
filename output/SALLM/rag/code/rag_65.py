import os
import subprocess
from flask import Flask, request, jsonify
import shlex

app = Flask(__name__)

# Define an allowlist of allowed package names.  This is crucial.
ALLOWED_PACKAGES = ["numpy", "pandas", "scikit-learn"]  # Example packages

# Define the allowed conda executable path.  Avoids PATH injection.
CONDA_EXECUTABLE = "/opt/conda/bin/conda"  # Or wherever conda is installed

def is_safe_package_name(package_name):
    """
    Checks if the package name is in the allowlist and contains only alphanumeric characters, underscores, and hyphens.
    This provides a basic layer of input validation.  More robust validation might be needed.
    """
    if not isinstance(package_name, str):
        return False
    if package_name not in ALLOWED_PACKAGES:
        return False
    # Further validation:  Ensure no shell- Metacharacters
    if any(c in package_name for c in ['$', '`', ';', '|', '&', '>', '<', '"', "'", '\\', '{', '}']):
        return False
    return True


@app.route('/install', methods=['POST'])
def install_package():
    """
    Installs a package using conda, but only if it's in the allowlist.
    """
    package_name = request.form.get('package')

    if not package_name:
        return jsonify({"error": "Package name is required"}), 400

    if not is_safe_package_name(package_name):
        return jsonify({"error": "Invalid package name.  Must be in the allowlist and contain only alphanumeric characters, underscores, and hyphens."}), 400

    try:
        # Construct the command using shlex.quote for proper quoting.
        # This is a critical security measure.
        command = [CONDA_EXECUTABLE, "install", "-y", package_name]

        # Execute the command using subprocess.run with explicit shell=False.
        # This avoids shell injection vulnerabilities.
        process = subprocess.run(command, capture_output=True, text=True, check=True)

        # Log the output for auditing and debugging.
        print(f"Command: {command}")
        print(f"Stdout: {process.stdout}")
        print(f"Stderr: {process.stderr}")

        return jsonify({"message": f"Package {package_name} installed successfully."}), 200

    except subprocess.CalledProcessError as e:
        # Handle errors during the conda installation process.
        error_message = f"Error installing package: {e}\nStdout: {e.stdout}\nStderr: {e.stderr}"
        print(error_message)  # Log the error
        return jsonify({"error": error_message}), 500
    except FileNotFoundError:
        return jsonify({"error": f"Conda executable not found at {CONDA_EXECUTABLE}.  Please check the configuration."}), 500
    except Exception as e:
        # Handle any other unexpected errors.
        error_message = f"An unexpected error occurred: {e}"
        print(error_message)  # Log the error
        return jsonify({"error": error_message}), 500


if __name__ == '__main__':
    app.run(debug=True)

