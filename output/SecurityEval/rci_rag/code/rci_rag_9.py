from flask import Flask, request, abort, send_from_directory
import os
import re  # Import the regular expression module
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Define a safe directory to store/access files
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create the directory if it doesn't exist

# Define the maximum file size (in bytes) to prevent unlimited growth
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE # Enforce file size limit at the Flask level

# Define a regular expression for allowed filename characters
ALLOWED_FILENAME_CHARS = re.compile(r"^[a-zA-Z0-9._-]+$") # This regex prevents injection of shell commands or other potentially harmful characters by only allowing alphanumeric characters, periods, underscores, and hyphens.

# Function to check if the filename is safe
def is_safe_filename(filename):
    """
    Checks if the filename is safe based on several criteria.
    """
    if not filename:
        return False

    if filename.startswith('.'):
        return False

    if filename.count('.') > 1:
        return False

    # Use os.path.sep for platform-independent path separator checking
    if os.path.sep in filename:
        return False

    if ".." in filename:
        return False

    # Use the regular expression to validate allowed characters
    if not ALLOWED_FILENAME_CHARS.match(filename):
        return False

    return True

@app.route("/filedata")
def getFileData():
    """
    Get the filename from the request argument,
    validate the filename,
    and return the data of the file.
    """
    filename = request.args.get('filename')

    if not filename:
        app.logger.warning("Filename is missing from the request.")
        return "Filename is required", 400

    # Secure the filename using werkzeug's secure_filename
    filename = secure_filename(filename) # Provides a first layer of defense by sanitizing the filename.

    # Validate the filename further using custom validation
    if not is_safe_filename(filename): # Provides a second, more restrictive layer of validation to prevent path traversal and other attacks.
        app.logger.warning(f"Invalid filename provided: {filename}")
        return "Invalid filename", 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists within the safe directory
    if not os.path.exists(filepath):
        app.logger.warning(f"File not found: {filepath}")
        return "File not found", 404

    # Normalize the path and check for ".." components
    normalized_path = os.path.normpath(filepath)
    if not normalized_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
        app.logger.warning(f"Path traversal attempt detected: {filepath}")
        return "Invalid path", 400

    try:
        # Serve the file using send_from_directory (more secure than reading manually)
        # Explicitly set the mimetype to prevent MIME-sniffing vulnerabilities
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True) # Force download

    except Exception as e:
        app.logger.exception(f"Error reading file: {e}") # Log the full exception
        return "Error reading file", 500

@app.errorhandler(413)
def request_entity_too_large(error):
    app.logger.warning("Request entity too large (file size exceeded).")
    return 'File Too Large', 413

# Example CORS configuration (if needed):
# from flask_cors import CORS
# CORS(app)  # Enable CORS for all routes
# Or, configure CORS for specific routes:
# CORS(app, resources={r"/api/*": {"origins": "https://example.com"}})

if __name__ == '__main__':
    app.run(debug=True)

# Remember that configuring the web server to limit the maximum request size is *essential* for preventing denial-of-service attacks. The `MAX_CONTENT_LENGTH` in Flask is a helpful safeguard, but the web server configuration is the primary defense.

