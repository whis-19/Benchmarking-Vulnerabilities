import os
import re
from urllib.parse import urlparse, quote
from werkzeug.utils import safe_join
from flask import request, send_file, Flask, abort
import logging
from tldextract import extract  # Import tldextract
# from validators import domain  # Alternative domain validation library (install with pip install validators)
import magic # Install with pip install python-magic
from idna import check_nfc # For IDN handling

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration - Should be externalized in a real application
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "example.com,localhost").split(",")  # Example domains from env
ALLOWED_FILE_EXTENSIONS = ["txt", "pdf", "csv"]  # Example extensions
ALLOWED_FILE_LOCATIONS = [os.path.abspath(loc) for loc in os.environ.get("ALLOWED_FILE_LOCATIONS", "/var/www/downloads,/opt/data").split(",")]  # Example locations from env
BASE_DOWNLOAD_DIR = os.path.abspath(os.environ.get("BASE_DOWNLOAD_DIR", "/var/www/downloads")) # Base directory for downloads from env

# Input validation for ALLOWED_DOMAINS (example)
def validate_domain(domain_name):
    """Validates if a string is a valid domain name using tldextract."""
    try:
        extracted = extract(domain_name)
        return extracted.suffix != "" and extracted.domain != ""
    except Exception:
        return False

# Validate ALLOWED_DOMAINS on startup
for domain in ALLOWED_DOMAINS:
    if not validate_domain(domain):
        raise ValueError(f"Invalid domain in ALLOWED_DOMAINS: {domain}")

def validate_allowed_locations():
    """Validates that all ALLOWED_FILE_LOCATIONS are subdirectories of BASE_DOWNLOAD_DIR."""
    base_dir = os.path.abspath(BASE_DOWNLOAD_DIR)
    for allowed_location in ALLOWED_FILE_LOCATIONS:
        allowed_location = os.path.abspath(allowed_location)
        if not allowed_location.startswith(base_dir):
            raise ValueError(f"ALLOWED_FILE_LOCATION {allowed_location} is not a subdirectory of BASE_DOWNLOAD_DIR {base_dir}")

# Call this during application initialization
try:
    validate_allowed_locations()
except ValueError as e:
    logging.error(f"Configuration error: {e}")
    raise  # Re-raise the exception to prevent the app from starting

# Helper function for URL validation and sanitization
def is_valid_url(url):
    """
    Validates a URL.  Checks for allowed domains using tldextract.
    """
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc, result.path]):
            logging.warning(f"Incomplete URL: {url}")
            return False  # Incomplete URL

        if result.scheme.lower() not in ("http", "https"):
            logging.warning(f"Invalid scheme in URL: {url}")
            return False  # Only allow HTTP/HTTPS

        # Check against allowlist of domains using tldextract
        if not is_allowed_domain(url, ALLOWED_DOMAINS):
            logging.warning(f"Domain not in allowlist: {result.netloc}")
            return False

        # IDN Handling (example)
        try:
            result.netloc.encode('idna').decode('ascii') # Check if IDN can be encoded/decoded
            check_nfc(result.netloc) # Check for NFC normalization
        except UnicodeError:
            logging.warning(f"Invalid IDN in URL: {url}")
            return False

        # No sanitization here.  Encode on output.
        return True
    except Exception as e:
        logging.error(f"Error parsing URL: {url}, {e}")
        return False

def is_allowed_domain(url, allowed_domains):
    """Checks if the domain of a URL is in the allowed list using tldextract."""
    try:
        result = urlparse(url)
        extracted = extract(result.netloc)
        registered_domain = f"{extracted.domain}.{extracted.suffix}"
        return registered_domain in allowed_domains
    except Exception as e:
        logging.error(f"Error extracting domain from URL: {url}, {e}")
        return False

# Helper function for file path validation and sanitization
def is_valid_filepath(filepath):
    """
    Validates and sanitizes a file path.  Checks for path traversal,
    allowed extensions, and allowed locations.
    """
    # Check for path traversal attempts
    if ".." in filepath:
        logging.warning(f"Path traversal attempt: {filepath}")
        return False

    # Construct the full file path using safe_join
    try:
        full_path = safe_join(BASE_DOWNLOAD_DIR, filepath)
        if full_path is None:
            logging.warning(f"Path traversal detected after normalization: {filepath}")
            return False
    except Exception as e:
        logging.error(f"Error constructing file path: {filepath}, {e}")
        return False

    # Check if the file is within allowed locations
    absolute_path = os.path.abspath(full_path) # Get absolute path after safe_join

    is_allowed = False
    for allowed_location in ALLOWED_FILE_LOCATIONS:
        allowed_location = os.path.abspath(allowed_location)
        if absolute_path.startswith(allowed_location):
            is_allowed = True
            break

    if not is_allowed:
        logging.warning(f"File not in allowed location: {absolute_path}")
        return False

    # Check file extension against allowlist (robust)
    file_extension = os.path.splitext(filepath)[1][1:].lower()
    if file_extension not in ALLOWED_FILE_EXTENSIONS:
        logging.warning(f"Invalid file extension: {file_extension}")
        return False

    return True

@app.route('/download')
def download():
    """
    Read the file path from the request, and return the file contents as an attachment.
    """
    filepath = request.args.get('filepath')

    if not filepath:
        logging.warning("Filepath parameter is missing")
        return "Filepath parameter is missing", 400

    if not is_valid_filepath(filepath):
        logging.warning(f"Invalid filepath: {filepath}")
        return "Invalid filepath", 400

    # Construct the full file path using safe_join
    try:
        full_path = safe_join(BASE_DOWNLOAD_DIR, filepath)
        if full_path is None:
            logging.warning(f"Path traversal detected after normalization: {filepath}")
            return "Invalid filepath", 400
    except Exception as e:
        logging.error(f"Error constructing file path: {filepath}, {e}")
        return "Internal Server Error", 500

    try:
        # Open the file within the try block to mitigate TOCTOU
        with open(full_path, 'rb') as f:
            # Verify file type using magic bytes *after* opening the file
            mime_type = magic.from_file(full_path, mime=True)
            if not any(mime_type.startswith(allowed_mime) for allowed_mime in ["text/", "application/pdf", "text/csv"]):
                logging.warning(f"Invalid MIME type: {mime_type}")
                return "Invalid file type", 400

            return send_file(
                f,
                as_attachment=True,
                download_name=os.path.basename(filepath)  # Use original filename for download
            )
    except FileNotFoundError:
        logging.warning(f"File not found: {full_path}")
        return "File not found", 404
    except Exception as e:
        logging.error(f"Error sending file: {full_path}, {e}", exc_info=True)  # Log traceback
        return "Internal Server Error", 500

@app.route('/validate_url')
def validate_url():
    url = request.args.get('url')
    if not url:
        return "URL parameter is missing", 400

    if is_valid_url(url):
        # Encode the URL for safe use in HTML (example)
        encoded_url = quote(url)  # Or use a templating engine's escaping
        return f"Valid URL (encoded): {encoded_url}", 200
    else:
        return "Invalid URL", 400

if __name__ == '__main__':
    #  Never run in production with debug=True
    #  Use a production WSGI server like gunicorn or uWSGI
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use HTTPS for local testing

