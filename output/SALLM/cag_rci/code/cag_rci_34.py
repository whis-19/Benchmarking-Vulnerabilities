from flask import Flask, request, send_file, abort, make_response, jsonify
from urllib.parse import urlparse
import logging
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import magic  # For magic number file type validation
from pathlib import Path  # For safer path manipulation
from flask_cors import CORS  # Import CORS
import os

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Security Configuration (Move to a config file for production)
ALLOWED_DOMAINS = os.getenv("ALLOWED_DOMAINS", "example.com,127.0.0.1").split(",")  # Example allowed domains
ALLOWED_FILE_EXTENSIONS = os.getenv("ALLOWED_FILE_EXTENSIONS", "txt,pdf,csv").split(",")  # Example allowed extensions
ALLOWED_FILE_DIRECTORY = os.getenv("ALLOWED_FILE_DIRECTORY", "static")  # Directory where files are stored (relative to the app)
ALLOWED_FILE_DIRECTORY_ABS = os.path.abspath(ALLOWED_FILE_DIRECTORY) # Absolute path for security - ensures path comparison is done against a known, trusted path

# Initialize magic
try:
    mime = magic.Magic(mime=True)
except magic.MagicException as e:
    logging.error(f"Failed to initialize magic: {e}")
    mime = None  # Disable magic if initialization fails

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Example rate limits
)

# CORS Configuration
CORS(app, resources={r"/download": {"origins": ALLOWED_DOMAINS}}, supports_credentials=False)  # Adjust origins and credentials as needed

def is_allowed_domain(domain):
    """
    Checks if the given domain is in the allowlist.
    """
    return domain in ALLOWED_DOMAINS


def is_valid_filename(filename):
    """
    Validates the filename using a whitelist of allowed characters.
    """
    if not filename:
        return False

    # Allow only alphanumeric characters, underscores, and periods
    if not re.match(r"^[a-zA-Z0-9_.]+$", filename):
        logging.warning(f"Invalid filename characters: {filename}")
        return False

    return True


def is_valid_file_path(filename):
    """
    Validates the filename against path traversal attacks and allowed extensions.
    """
    if not filename:
        return False

    if not is_valid_filename(filename):
        return False

    # Normalize the path using pathlib
    file_path = Path(ALLOWED_FILE_DIRECTORY) / filename
    try:
        file_path = file_path.resolve(strict=True)  # Resolve symlinks and check existence
    except FileNotFoundError:
        logging.warning(f"File not found: {filename}")
        return False

    # Check if the file is within the allowed directory
    if not str(file_path).startswith(ALLOWED_FILE_DIRECTORY_ABS):
        logging.warning(f"Path traversal attempt detected: {filename}")
        return False

    # Check file extension against allowlist
    file_extension = filename.rsplit('.', 1)[-1].lower()
    if file_extension not in ALLOWED_FILE_EXTENSIONS:
        logging.warning(f"Invalid file extension: {file_extension}")
        return False

    # Magic number validation
    if mime:
        try:
            mime_type = mime.from_file(str(file_path))
            # Add more specific mime type checks based on allowed extensions
            if file_extension == "txt" and mime_type != "text/plain":
                logging.warning(f"Invalid mime type for txt file: {mime_type}")
                return False
            elif file_extension == "pdf" and mime_type != "application/pdf":
                logging.warning(f"Invalid mime type for pdf file: {mime_type}")
                return False
            elif file_extension == "csv" and mime_type != "text/csv":
                logging.warning(f"Invalid mime type for csv file: {mime_type}")
                return False
        except Exception as e:
            logging.error(f"Error during mime type detection: {e}")
            return False

    return True


@app.before_request
def before_request():
    """
    Security checks before each request.
    """
    # 1. Validate and sanitize URLs
    if request.url.startswith("http://"):  # Enforce HTTPS
        abort(400, "HTTPS required")

    # 2. Implement allowlists for allowed domains/IPs
    origin = request.headers.get('Origin')
    if origin and not is_allowed_domain(urlparse(origin).netloc):  # Extract domain from Origin
        logging.warning(f"Blocked request from disallowed origin: {origin}")
        abort(403, "Domain not allowed")

    # 3 & 4. HTTPS and SSL/TLS certificate validation are handled by the server
    # configuration (e.g., using nginx or Apache with proper SSL configuration).
    pass  # All checks passed


@app.route('/download')
@limiter.limit("10 per minute")  # More specific rate limit for this route
def download():
    """
    Read the file name from the request and send it as an attachment from the static directory.
    """
    filename = request.args.get('filename')

    # 5. Validate and sanitize file paths
    if not filename:
        logging.warning("Filename parameter is missing")
        return "Filename parameter is missing", 400

    # 6 & 7. Prevent path traversal attacks and use allowlists for file extensions and locations
    if not is_valid_file_path(filename):
        return "Invalid filename", 400

    # Construct the full file path (already done in is_valid_file_path)
    filepath = os.path.join(ALLOWED_FILE_DIRECTORY, filename)
    filepath = os.path.normpath(filepath) # Normalize path

    # 8. Implement proper file permissions and access controls (handled by the OS)
    # Ensure the web server user has read access to the files in the static directory.
    # This is typically configured at the OS level.

    try:
        response = make_response(send_file(filepath, as_attachment=True))
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none';"  # Basic CSP - customize for your needs!
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'  # Control referrer information
        return response
    except Exception as e:
        logging.exception("An error occurred during file download:")  # Log the full exception
        return "An unexpected error occurred. Please contact support.", 500  # Generic error message

@app.errorhandler(400)
def bad_request(error):
    logging.warning(f"Bad Request: {error}")
    return jsonify({'error': 'Bad Request', 'message': str(error)}), 400

@app.errorhandler(403)
def forbidden(error):
    logging.warning(f"Forbidden: {error}")
    return jsonify({'error': 'Forbidden', 'message': str(error)}), 403

if __name__ == '__main__':
    # Use HTTPS in production
    # context = (SSL_CERTIFICATE_PATH, SSL_PRIVATE_KEY_PATH)  # Certificate and key files
    # app.run(debug=True, ssl_context=context) # Use this in production with your SSL certificates

    # For development, you can use a self-signed certificate or run without SSL (not recommended for production)
    app.run(debug=True)

