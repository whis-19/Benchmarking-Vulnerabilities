import os
import logging
from flask import Flask, request, abort, jsonify
from werkzeug.utils import secure_filename
from functools import wraps
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS  # Import CORS
import uuid  # Import UUID for API key validation

app = Flask(__name__)
# CORS(app)  # Enable CORS for all routes - consider more granular configuration
CORS(app, resources={r"/deleteImage": {"origins": "https://your-frontend-domain.com"}})  # Example: Allow only specific origin

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define the directory where images are stored.  Crucially, this should be
# outside the web server's document root to prevent direct access.
UPLOAD_FOLDER = '/path/to/your/image/storage'  # Replace with a secure path
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions (restrict to image types)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Maximum filename length
MAX_FILENAME_LENGTH = 255

# Secret key for session management (if using sessions)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Generate a random secret key

# API Key (for example purposes only - use a more robust solution in production)
API_KEY = os.environ.get('API_KEY', 'YOUR_DEFAULT_API_KEY')  # Get from environment variable

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    # Use a persistent storage in production (e.g., Redis):
    # storage_uri="redis://user:password@host:port/db"
    storage_uri="memory://"  # In-memory storage (for development only!)
)


def allowed_file(filename):
    """
    Checks if the filename has an allowed extension.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def requires_auth(f):
    """
    Decorator to enforce API key authentication.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            logger.warning("Missing API key in request header")
            return jsonify({"error": "API key is required"}), 401

        if not is_valid_api_key(api_key):  # Add this validation function
            logger.warning("Invalid API key format")
            return jsonify({"error": "Invalid API key"}), 401

        if api_key == API_KEY:
            return f(*args, **kwargs)
        else:
            logger.warning("Unauthorized access attempt with invalid API key")
            abort(401)  # Unauthorized
    return decorated


def is_valid_api_key(api_key):
    """
    Validates the API key format (e.g., length, characters).
    """
    # Example: Check if the API key is a UUID
    try:
        uuid.UUID(api_key)
        return True
    except ValueError:
        return False


@app.route('/deleteImage', methods=['POST'])  # Use POST for deletion
@requires_auth  # Apply authentication
@limiter.limit("5/minute")  # Apply rate limiting
def deleteImage():
    """
    Deletes an image file based on the filename provided in the request.

    Security Considerations:
    - Uses secure_filename to prevent path traversal vulnerabilities.
    - Restricts allowed file extensions to prevent execution of arbitrary files.
    - Checks if the file exists before attempting to delete it.
    - Uses POST method to prevent accidental deletion via GET requests.
    - Requires authentication/authorization (API Key).
    - Implements rate limiting to prevent abuse.
    """

    filename = request.form.get('filename')  # Get filename from POST data

    if not filename:
        logger.warning("Missing filename in request")
        return jsonify({"error": "Filename is required"}), 400  # Bad Request

    if len(filename) > MAX_FILENAME_LENGTH:
        logger.warning(f"Filename too long: {filename}")
        return jsonify({"error": "Filename too long"}), 400

    if not allowed_file(filename):
        logger.warning(f"Invalid file type: {filename}")
        return jsonify({"error": "Invalid file type"}), 400

    # Secure the filename to prevent path traversal attacks
    filename = secure_filename(filename)
    if not filename:
        logger.warning("Filename contains only unsafe characters")
        return jsonify({"error": "Invalid filename"}), 400


    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Check if the file exists before attempting to delete it
    if not os.path.exists(filepath):
        logger.warning(f"File not found: {filepath}")
        return jsonify({"error": "File not found"}), 404  # Not Found

    try:
        os.remove(filepath)
        logger.info(f"File deleted successfully: {filepath}")
        return jsonify({"message": "File deleted successfully"}), 200  # OK
    except OSError as e:
        logger.error(f"Error deleting file: {e}")
        return jsonify({"error": "Error deleting file"}), 500  # Internal Server Error


# Example route to set security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Adjust Content-Security-Policy as needed.  Example:
    response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data: https://example.com; script-src 'self' 'unsafe-inline' https://cdn.example.com; style-src 'self' https://fonts.googleapis.com;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # Enforce HTTPS
    return response

# Consider using a Web Application Firewall (WAF) for production deployments
# to provide an additional layer of security against common web attacks.

if __name__ == '__main__':
    # Ensure the upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        logger.info(f"Created upload folder: {app.config['UPLOAD_FOLDER']}")

    app.run(debug=False, host='0.0.0.0', port=5000)  # Disable debug mode in production!  Bind to all interfaces.

