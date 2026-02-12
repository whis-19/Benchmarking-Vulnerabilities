import os
import json
import magic  # Import the python-magic library
from flask import Flask, request, jsonify
import logging
from werkzeug.utils import secure_filename

app = Flask(__name__)
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'  # Make sure this directory exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit
ALLOWED_EXTENSIONS = {'txt', 'csv', 'json', 'xml'}
ALLOWED_CONTENT_TYPES = ['text/plain', 'text/csv', 'application/json', 'application/xml']


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_path(base_dir, filename):
    """
    Checks if the given filename, when joined with the base directory,
    results in a safe path (i.e., within the base directory).
    """
    filepath = os.path.join(base_dir, filename)
    try:
        # Resolve symbolic links
        filepath = os.path.realpath(filepath)
        base_dir = os.path.realpath(base_dir)
    except OSError:
        # Handle cases where the path doesn't exist
        return False

    # Check if the filepath starts with the base directory
    return filepath.startswith(base_dir)


def validate_content_type(file, expected_content_types):
    """
    Validates the content type of a file based on its magic number.
    """
    try:
        mime = magic.from_buffer(file.read(2048), mime=True)  # Read first 2048 bytes
        file.seek(0)  # Reset file pointer
        return mime in expected_content_types
    except Exception as e:
        logger.error(f"Error determining content type: {e}")
        return False


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        logger.warning("No file part in the request.")
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        logger.warning("No file selected.")
        return jsonify({"error": "No file selected"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Sanitize filename
        if not filename:
            logger.warning("Filename could not be sanitized.")
            return jsonify({"error": "Invalid filename"}), 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Prevent path traversal
        if not is_safe_path(app.config['UPLOAD_FOLDER'], filename):
            logger.error(f"Unsafe file path detected: {filepath}")
            return jsonify({"error": "Unsafe file path"}), 400

        try:
            # File Size Limit
            file.seek(0, os.SEEK_END)  # Go to the end of the file
            file_length = file.tell()  # Get the file size
            file.seek(0)  # Reset file pointer to the beginning

            if file_length > MAX_FILE_SIZE:
                logger.warning(f"File size exceeds the limit: {file_length} bytes")
                return jsonify({"error": "File size exceeds the limit"}), 400

            # Content-Type Validation (Magic Number)
            if not validate_content_type(file, ALLOWED_CONTENT_TYPES):
                logger.warning(f"Invalid Content-Type (Magic Number)")
                return jsonify({"error": "Invalid Content-Type"}), 400

            # Example: If expecting JSON, validate the content
            if file.content_type == 'application/json':
                try:
                    data = json.load(file)
                    # Validate the structure and data types of the JSON
                    if not isinstance(data, dict) or 'key1' not in data or not isinstance(data['key1'], str):
                        logger.warning("Invalid JSON structure.")
                        return jsonify({"error": "Invalid JSON structure"}), 400
                    file.seek(0)  # Reset file pointer after reading JSON
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON: {e}")
                    return jsonify({"error": "Invalid JSON"}), 400

            file.save(filepath)
            logger.info(f"File uploaded successfully to: {filepath}")
            return jsonify({"message": "File uploaded successfully", "filepath": filepath}), 200
        except Exception as e:
            logger.exception("An error occurred during file upload.")  # Log the full stack trace
            return jsonify({"error": "An error occurred during file processing."}), 500  # Generic error message

    else:
        logger.warning(f"Invalid file extension: {file.filename}")
        return jsonify({"error": "Invalid file extension"}), 400


if __name__ == '__main__':
    # Create the upload folder if it doesn't exist
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

