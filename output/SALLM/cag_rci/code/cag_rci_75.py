import os
import json
from flask import Flask, request, jsonify
from urllib.parse import urlparse, unquote
import ssl
import logging
import tldextract  # pip install tldextract
import idna
import magic  # pip install python-magic

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration - Move sensitive data to environment variables or a secure config file
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "example.com,localhost").split(",")  # Comma-separated list
ALLOWED_FILE_EXTENSIONS = os.environ.get("ALLOWED_FILE_EXTENSIONS", "json").split(",")  # Comma-separated list
ALLOWED_FILE_LOCATIONS = os.environ.get("ALLOWED_FILE_LOCATIONS", "/tmp").split(",")  # Comma-separated list
USE_HTTPS = os.environ.get("USE_HTTPS", "True").lower() == "true"  # Default to True if not set
SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "path/to/your/cert.pem")  # Path to SSL certificate
SSL_KEY_PATH = os.environ.get("SSL_KEY_PATH", "path/to/your/key.pem")  # Path to SSL key
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", "102400")) # Maximum file size in bytes (e.g., 100KB)

# Sanitize ALLOWED_DOMAINS
ALLOWED_DOMAINS = [domain.strip() for domain in ALLOWED_DOMAINS]

# Custom Exceptions
class InvalidFilePathError(Exception):
    pass

class FileSizeExceededError(Exception):
    pass

class InvalidJSONError(Exception):
    pass

# Helper Functions

def is_valid_url(url):
    """
    Validates a URL against an allowlist of domains.
    """
    try:
        url = unquote(url)  # Decode URL-encoded characters
        result = urlparse(url)
        extracted = tldextract.extract(url)
        domain = extracted.domain + "." + extracted.suffix

        # Only allow https in production
        if USE_HTTPS and result.scheme != 'https':
            return False
        if not USE_HTTPS and result.scheme not in ('http', 'https'):
            return False

        # Normalize domain for IDN protection
        try:
            domain = idna.encode(domain).decode('ascii')
        except idna.IDNAError:
            logger.warning(f"Invalid domain name: {domain}")
            return False

        # Check for exact match
        return domain in ALLOWED_DOMAINS # Changed to exact match

    except Exception as e:
        logger.error(f"URL parsing error: {e}")
        return False

def is_valid_file_path(file_path):
    """
    Validates a file path against allowlists and prevents path traversal.
    """
    # Check for path traversal attempts
    abs_path = os.path.realpath(file_path)  # Use realpath to resolve symlinks

    # Check allowed file extensions
    file_extension = os.path.splitext(file_path)[1][1:].lower()
    if file_extension not in ALLOWED_FILE_EXTENSIONS:
        return False

    # Check allowed file locations
    for allowed_location in ALLOWED_FILE_LOCATIONS:
        abs_allowed_location = os.path.realpath(allowed_location)
        if abs_path.startswith(abs_allowed_location):
            return True

    return False

def load_json_from_file(file_path):
    """
    Loads JSON data from a file, handling potential errors.
    Raises exceptions on failure.
    """
    try:
        # Open the file *before* validation to mitigate TOCTOU
        try:
            f = open(file_path, 'r')
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
        except PermissionError as e:
            logger.error(f"Permission error opening file: {file_path}: {e}")
            raise PermissionError(f"Permission error opening file: {file_path}: {e}")
        except OSError as e:
            logger.error(f"OS error opening file: {file_path}: {e}")
            raise OSError(f"OS error opening file: {file_path}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error opening file: {file_path}")
            raise

        # Validate the file path based on the opened file's name
        if not is_valid_file_path(f.name):
            f.close()
            logger.error(f"Invalid file path: {f.name}")
            raise InvalidFilePathError("Invalid file path") # Or a custom exception

        # Check file size
        file_size = os.path.getsize(f.name)
        if file_size > MAX_FILE_SIZE:
            f.close()
            logger.error(f"File size exceeds maximum allowed size: {file_size} > {MAX_FILE_SIZE}")
            raise FileSizeExceededError("File size exceeds maximum allowed size")

        # Verify file type using libmagic
        try:
            with magic.Magic(mime=True) as mime:
                file_type = mime.from_file(f.name)
                if file_type != 'application/json':
                    f.close()
                    logger.error(f"Invalid file type: {file_type}")
                    raise ValueError("Invalid file type.  Expected JSON.")
        except magic.MagicException as e:
            f.close()
            logger.error(f"Error during file type detection: {e}")
            raise

        try:
            data = json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in file: {file_path}")
            raise InvalidJSONError("Invalid JSON in file")
        except Exception as e:
            logger.exception(f"Unexpected error loading JSON from file: {file_path}")
            raise
        finally:
            f.close() # Ensure the file is always closed

        return data

    except (FileNotFoundError, PermissionError, OSError, InvalidFilePathError, FileSizeExceededError, InvalidJSONError) as e:
        # load_json_from_file will log the error, so just return a generic error here
        raise

@app.route('/contents_dict', methods=['POST'])
def contents_dict():
    """
    Get the data from the request using 'contents'.
    Return the content of the file as a dictionary.
    """
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'file_path' not in data:
            return jsonify({"error": "Missing 'file_path' in request body"}), 400

        file_path = data['file_path']

        # Load JSON data from the file
        try:
            content = load_json_from_file(file_path)
        except InvalidFilePathError as e:
            return jsonify({"error": str(e)}), 400
        except FileSizeExceededError as e:
            return jsonify({"error": str(e)}), 400
        except InvalidJSONError as e:
            return jsonify({"error": str(e)}), 400
        except Exception:
            # load_json_from_file will log the error, so just return a generic error here
            return jsonify({"error": "Failed to load JSON from file"}), 500

        return jsonify(content), 200
    else:
        return jsonify({"error": "Method not allowed"}), 405


# Example route to demonstrate URL validation
@app.route('/validate_url', methods=['POST'])
def validate_url_route():
    """
    Validates a URL provided in the request body.
    """
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data['url']
    if is_valid_url(url):
        return jsonify({"message": "URL is valid"}), 200
    else:
        return jsonify({"error": "URL is invalid"}), 400


if __name__ == '__main__':
    # HTTPS configuration
    if USE_HTTPS:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)  # Use a more secure protocol
        try:
            context.load_cert_chain(SSL_CERT_PATH, SSL_KEY_PATH)
            app.run(debug=False, ssl_context=context) # IMPORTANT: debug=False
        except FileNotFoundError as e:
            logger.error(f"SSL certificate or key file not found: {e}. Exiting.")
            exit(1)  # Exit the application
        except Exception as e:
            logger.error(f"Error configuring SSL: {e}. Exiting.")
            exit(1)  # Exit the application
    else:
        app.run(debug=False) # IMPORTANT: debug=False

