import os
from functools import wraps
from flask import Flask, send_file, abort, request
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
import mimetypes
import re
import logging
import magic  # For content type validation

app = Flask(__name__)

# Configuration
UPLOAD_FOLDER = 'images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def allowed_file(filename):
    """Checks if the filename has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_path(path, base):
    """
    Checks if the given path is a safe path relative to the base directory.
    This function normalizes the path and checks for ".." components.
    """
    normalized_path = os.path.normpath(path)
    return base == os.path.commonpath((base, normalized_path))


def validate_url(url):
    """
    Validates the provided URL to prevent Server-Side Request Forgery (SSRF).
    """
    try:
        result = urlparse(url)
        if not result.scheme or not result.netloc:
            return False  # Invalid URL format

        # Restrict allowed schemes
        if result.scheme not in ('http', 'https'):
            return False

        # Check the hostname against a whitelist using regular expressions
        allowed_hosts = [r'^example\.com$', r'^.*\.(sub\.example\.net)$']  # More specific regexes
        hostname = result.hostname
        if not any(re.match(pattern, hostname) for pattern in allowed_hosts):
            return False  # Hostname not allowed

        # Block private IP addresses
        if result.hostname in ('127.0.0.1', 'localhost') or result.hostname.startswith(('192.168.', '10.', '172.16.')):
            return False

        return True  # URL is valid
    except Exception as e:
        logging.error(f"URL validation error: {e}")
        return False  # URL parsing error


def image_route(f):
    """Decorator to handle image requests securely."""

    @wraps(f)
    def decorated_function(filename):
        """
        Handles the image request, validating the filename and serving the file.
        """
        if not filename:
            abort(400, "Filename is required.")

        # Secure the filename using werkzeug's secure_filename
        filename = secure_filename(filename)

        # Validate filename (more robust than just secure_filename)
        if not filename:
            abort(400, "Invalid filename.")

        if ".." in filename or "/" in filename or "\\" in filename:
            abort(400, "Invalid filename: contains path separators or '..' sequences.")

        if filename.count('.') > 1:
            abort(400, "Invalid filename: contains multiple '.' characters.")

        if not allowed_file(filename):
            abort(400, "Invalid file type.")

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Check if the path is safe
        if not is_safe_path(filepath, os.path.abspath(app.config['UPLOAD_FOLDER'])):
            abort(400, "Invalid filename: path traversal detected.")

        if os.path.exists(filepath):
            try:
                # Content type validation using python-magic
                try:
                    mime = magic.Magic(mime=True)
                    content_type = mime.from_file(filepath)
                except magic.MagicException as e:
                    logging.warning(f"Error determining content type with magic: {e}")
                    content_type = None  # Fallback to mimetypes.guess_type

                if not content_type:
                    content_type = mimetypes.guess_type(filepath)[0]

                if content_type:
                    return send_file(filepath, mimetype=content_type)
                else:
                    return send_file(filepath)  # Let Flask try to guess, or set a default
            except Exception as e:
                logging.error(f"Error sending file: {e}", exc_info=True)  # Log with traceback
                abort(500, "Error sending file.")
        else:
            abort(404, "File not found.")

    return decorated_function


@app.route('/images/<filename>')
@image_route
def get_image(filename):
    """
    Route to serve images.  The image_route decorator handles the security.
    """
    pass  # The decorator handles the logic


@app.route('/validate_url')
def validate_url_route():
    """
    Example route to demonstrate URL validation.
    """
    target_url = request.args.get('url')
    if not target_url:
        return "Please provide a URL.", 400

    if validate_url(target_url):
        return f"URL '{target_url}' is valid."
    else:
        return f"URL '{target_url}' is invalid.", 400


if __name__ == '__main__':
    app.run(debug=True)

