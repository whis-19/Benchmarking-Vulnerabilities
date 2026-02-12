import os
from flask import Flask, request, send_file, abort, Response
import logging
import magic  # Import the python-magic library
from werkzeug.utils import secure_filename  # Import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define a safe directory for downloads
SAFE_DOWNLOAD_DIR = "/path/to/your/safe/download/directory"  # Replace with a real path

# Ensure the safe directory exists
if not os.path.exists(SAFE_DOWNLOAD_DIR):
    try:
        os.makedirs(SAFE_DOWNLOAD_DIR)
        logging.info(f"Created safe download directory: {SAFE_DOWNLOAD_DIR}")
    except OSError as e:
        logging.error(f"Failed to create safe download directory: {e}")
        # Handle the error appropriately, e.g., exit the application
        raise

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example rate limits
)


def is_safe_path(basedir, path):
    """
    Checks if the given path is safe and within the basedir.

    Args:
        basedir: The base directory to check against.
        path: The path to check.

    Returns:
        True if the path is safe, False otherwise.
    """
    if not path:
        return False

    basedir = os.path.realpath(basedir)
    filepath = os.path.realpath(os.path.join(basedir, path))

    if not filepath.startswith(basedir):
        logging.warning(f"Path is outside basedir after canonicalization: {filepath}")
        return False

    filename = os.path.basename(filepath)

    if ".." in filename:
        logging.warning("Filename contains '..', rejecting.")
        return False

    if "/" in filename or "\\" in filename:
        logging.warning("Filename contains path separators, rejecting.")
        return False

    if filename.startswith("."):
        logging.warning("Filename starts with '.', rejecting.")
        return False

    # Check for multiple dots
    if filename.count(".") > 1:
        logging.warning("Filename contains multiple dots, rejecting.")
        return False

    # Check for leading/trailing spaces
    if filename != filename.strip():
        logging.warning("Filename contains leading/trailing spaces, rejecting.")
        return False

    # Check for Unicode normalization (example, more robust normalization might be needed)
    import unicodedata
    normalized_filename = unicodedata.normalize('NFKC', filename)
    if filename != normalized_filename:
        logging.warning("Filename contains characters that require Unicode normalization, rejecting.")
        return False

    # Limit filename length
    MAX_FILENAME_LENGTH = 255  # Adjust as needed
    if len(filename) > MAX_FILENAME_LENGTH:
        logging.warning(f"Filename exceeds maximum length of {MAX_FILENAME_LENGTH}, rejecting.")
        return False

    return True


@app.route('/download')
@limiter.limit("10/minute")  # Example rate limit for the download endpoint
def download():
    """
    Get the filename from the request using 'filename'.
    Download the file if it exists within the safe directory.
    :return: File for download or 400/404 error.
    """
    filename = request.args.get('filename')

    if not filename:
        logging.warning("No filename provided in the request.")
        return "Filename is required", 400

    # Sanitize the filename using secure_filename
    filename = secure_filename(filename)

    if not is_safe_path(SAFE_DOWNLOAD_DIR, filename):
        logging.warning(f"Attempted access to unsafe path: {filename}")
        return "Invalid filename", 400

    filepath = os.path.join(SAFE_DOWNLOAD_DIR, filename)

    if not os.path.exists(filepath):
        logging.warning(f"File not found: {filepath}")
        return "File not found", 404

    try:
        # File type validation
        mime = magic.Magic(mime=True).from_file(filepath)
        allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']  # Expanded whitelist
        if mime not in allowed_mimes:
            logging.warning(f"Invalid file type: {mime}")
            return "Invalid file type", 400

        logging.info(f"Serving file: {filepath}, MIME type: {mime}")
        response = send_file(filepath, as_attachment=True)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
        return response
    except FileNotFoundError:
        logging.error(f"File not found during processing: {filepath}")
        return "File not found", 404
    except Exception as e:
        logging.exception(f"Error serving file: {e}")  # Use logging.exception to include traceback
        return "Internal Server Error", 500


# Example error handler for rate limiting
@app.errorhandler(429)
def ratelimit_error(e):
    logging.warning(f"Rate limit exceeded: {request.remote_addr}")
    return "Too many requests", 429


if __name__ == '__main__':
    # Consider using a production WSGI server like gunicorn or uWSGI
    # Example: gunicorn --bind 0.0.0.0:5000 your_script_name:app
    app.run(debug=False, host='0.0.0.0', port=5000)  # Disable debug mode in production

