import os
import subprocess
import re
import tempfile
import logging
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from flask_talisman import Talisman
import magic  # Requires python-magic

app = Flask(__name__)
talisman = Talisman(app)  # Initialize Flask-Talisman

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define allowed characters for package names to prevent command injection
ALLOWED_PACKAGE_NAME_CHARS = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")  # Added length limit

# Define a directory to store temporary files (if needed)
UPLOAD_FOLDER = '/tmp/uploads'  # Consider a more secure location
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# File size limit (in bytes) - e.g., 10MB
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

# Allowed conda channels
ALLOWED_CHANNELS = ['conda-forge', 'defaults']  # Example channels

# User to run conda as
CONDA_USER = 'condauser'  # Replace with the actual user

# Whitelist of allowed package names
ALLOWED_PACKAGES = ['numpy', 'pandas', 'scikit-learn']  # Replace with your allowed packages

def is_package_name_safe(package_name):
    """
    Checks if the package name is safe to use.  Now checks against a whitelist.
    """
    return package_name in ALLOWED_PACKAGES  # Check against whitelist


@app.route('/install', methods=['POST'])
def install_package():
    """
    Get the package from the request using 'package'.
    Install the package using conda.
    Return the package name.  Handles both package name and file uploads.
    """
    if 'package' in request.form:
        package_name = request.form['package']

        if not package_name:
            return jsonify({'error': 'Package name cannot be empty'}), 400

        if not is_package_name_safe(package_name):
            return jsonify({'error': 'Invalid package name.  Only allowed packages can be installed.'}), 400

        try:
            # Construct the conda install command.  Use subprocess.run with shell=False for safety.
            command = ['conda', 'install', '-y', package_name]  # -y flag to automatically answer yes to prompts

            # Add channel restrictions
            for channel in ALLOWED_CHANNELS:
                command.extend(['-c', channel])

            # Run conda as a specific user
            command = ['sudo', '-u', CONDA_USER] + command

            result = subprocess.run(command, capture_output=True, text=True, check=True)  # check=True raises an exception on non-zero exit code

            # Log the output for debugging
            logging.info(f"Conda install output: {result.stdout}")
            logging.info(f"Conda install errors: {result.stderr}")

            return jsonify({'message': f'Package {package_name} installed successfully'}), 200

        except subprocess.CalledProcessError as e:
            # Handle errors from the conda command
            error_message = f"Error installing package: {e.stderr}"
            logging.error(error_message)  # Log the detailed error
            return jsonify({'error': 'Failed to install package.  See logs for details.'}), 500  # Generic error message for the user
        except Exception as e:
            # Handle other unexpected errors
            error_message = f"An unexpected error occurred: {str(e)}"
            logging.exception(e)
            return jsonify({'error': 'An unexpected error occurred. See logs for details.'}), 500

    elif 'file' in request.files:
        # Handle file uploads (e.g., a conda package file)
        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        try:
            # Content type validation using python-magic
            mime = magic.Magic(mime=True)
            file.seek(0)  # Ensure file pointer is at the beginning
            file_mime_type = mime.from_buffer(file.read(2048))  # Read first 2048 bytes
            file.seek(0)  # Reset file pointer after reading

            if file_mime_type != 'application/x-bzip2':  # More specific mime type
                return jsonify({'error': 'Invalid file type. Only conda packages (.tar.bz2) are allowed.'}), 400

            # File extension check (additional layer)
            if not file.filename.endswith(".tar.bz2"):
                return jsonify({'error': 'Invalid file extension. Only .tar.bz2 files are allowed.'}), 400

        except magic.MagicException as e:
            logging.error(f"Error during mime type detection: {e}")
            return jsonify({'error': 'Error detecting file type.'}), 500
        except Exception as e:
            logging.exception(f"Unexpected error during file validation: {e}")
            return jsonify({'error': 'Error validating file.'}), 500

        try:
            # Use NamedTemporaryFile for secure temporary file handling
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.bz2") as tmp_file:
                file.save(tmp_file.name)
                filepath = tmp_file.name

            # Install from the file
            command = ['conda', 'install', '-y', filepath]

            # Add channel restrictions
            for channel in ALLOWED_CHANNELS:
                command.extend(['-c', channel])

            # Run conda as a specific user
            command = ['sudo', '-u', CONDA_USER] + command

            result = subprocess.run(command, capture_output=True, text=True, check=True)

            logging.info(f"Conda install output: {result.stdout}")
            logging.info(f"Conda install errors: {result.stderr}")

            # Clean up the temporary file
            os.remove(filepath)

            return jsonify({'message': f'Package from file installed successfully'}), 200

        except subprocess.CalledProcessError as e:
            error_message = f"Error installing package from file: {e.stderr}"
            logging.error(error_message)
            return jsonify({'error': 'Failed to install package from file. See logs for details.'}), 500
        except Exception as e:
            error_message = f"An unexpected error occurred: {str(e)}"
            logging.exception(e)
            return jsonify({'error': 'An unexpected error occurred. See logs for details.'}), 500

    else:
        return jsonify({'error': 'No package name or file provided'}), 400


if __name__ == '__main__':
    app.run(debug=True)

