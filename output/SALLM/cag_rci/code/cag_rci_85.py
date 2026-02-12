import os
from flask import Flask, request, send_file, abort
from urllib.parse import urlparse
import mimetypes
import re  # For filename sanitization
import logging
import tldextract  # For more robust domain extraction

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration -  Move to a config file or environment variables in production
ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example allowed domains
ALLOWED_FILE_EXTENSIONS = [".txt", ".pdf", ".csv"]  # Example allowed extensions
BASE_DOWNLOAD_DIR = "/var/www/downloads" # Base directory for downloads.  Crucial for security.
MAX_FILE_SIZE = 1024 * 1024 * 10  # 10MB limit

def is_valid_domain(url):
    """
    Checks if the domain in the URL is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logging.warning(f"Invalid URL: No domain provided: {url}")
            return False  # No domain provided

        # Use tldextract for more robust domain extraction
        extracted = tldextract.extract(parsed_url.netloc)
        domain = f"{extracted.domain}.{extracted.suffix}"

        if domain not in ALLOWED_DOMAINS:
            logging.warning(f"Invalid URL: Domain not allowed: {domain} in {url}")
            return False

        if parsed_url.scheme not in ["http", "https"]:
            logging.warning(f"Invalid URL: Scheme not allowed: {parsed_url.scheme} in {url}")
            return False

        return True
    except ValueError as e:  # Catch specific URL parsing errors
        logging.error(f"Error parsing URL: {url} - {e}")
        return False  # Invalid URL format

def sanitize_filename(filename, max_length=255):  # Adjust max_length as needed
    """
    Sanitizes a filename to remove potentially dangerous characters and limit length.
    """
    filename = re.sub(r"[^a-zA-Z0-9._-]", "", filename) # Whitelist approach
    filename = filename[:max_length]
    if not filename:
        logging.warning("Sanitized filename is empty.")
        return "default_filename"  # Or raise an exception

    return filename

def is_safe_path(path):
    """
    Checks if the path is safe, preventing path traversal attacks.
    """
    normalized_path = os.path.normpath(path)

    # Check for ".." patterns
    if ".." in normalized_path:
        logging.warning(f"Path traversal detected: {path}")
        return False

    # Check if the path starts with a slash (absolute path injection)
    if normalized_path.startswith("/"):
        logging.warning(f"Absolute path injection detected: {path}")
        return False

    return True

def is_allowed_file_extension(filename):
    """
    Checks if the file extension is in the allowlist.
    """
    _, ext = os.path.splitext(filename)
    ext = ext.lower()
    if ext not in ALLOWED_FILE_EXTENSIONS:
        logging.warning(f"Disallowed file extension: {ext} in {filename}")
        return False
    return True

@app.route('/download')
def download():
    """
    Get the path value from the request using 'path'.
    Download the file by taking the path parameter from the request.
    :return: path
    """
    filepath = request.args.get('path')

    if not filepath:
        logging.warning("Filepath parameter is missing")
        return "Filepath parameter is missing", 400

    # Validate and sanitize the filepath
    if not is_safe_path(filepath):
        return "Invalid filepath: Path traversal detected or outside allowed locations", 400

    if not is_allowed_file_extension(filepath):
        return "Invalid file extension", 400

    # Sanitize the filename
    filepath = sanitize_filename(filepath)

    # Construct the full path to the file.  Crucially, use os.path.join with a base directory.
    full_path = os.path.join(BASE_DOWNLOAD_DIR, filepath)

    # Check if the file exists
    if not os.path.exists(full_path):
        logging.warning(f"File not found: {full_path}")
        return "File not found", 404

    # Check if it's a file and not a directory
    if not os.path.isfile(full_path):
        logging.warning(f"Invalid request: Not a file: {full_path}")
        return "Invalid request: Not a file", 400

    # Check file size
    file_size = os.path.getsize(full_path)
    if file_size > MAX_FILE_SIZE:
        logging.warning(f"File too large: {full_path} - Size: {file_size}")
        return "File too large", 413  # Request Entity Too Large

    try:
        # Send the file with appropriate headers
        content_type, encoding = mimetypes.guess_type(full_path)
        if content_type is None:
            content_type = 'application/octet-stream'  # Default binary type

        response = send_file(full_path, as_attachment=True, mimetype=content_type)
        # Add security headers (example)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    except FileNotFoundError as e:
        logging.error(f"Error sending file (File Not Found): {full_path} - {e}")
        return "File not found", 404
    except Exception as e:
        logging.error(f"Error sending file: {full_path} - {e}")  # Log the error
        return "Error sending file", 500

# Example route demonstrating URL validation (if you need to handle URLs)
@app.route('/proxy')
def proxy():
    """
    Example route to proxy a request to a URL.  Demonstrates URL validation.
    """
    target_url = request.args.get('url')

    if not target_url:
        logging.warning("URL parameter is missing")
        return "URL parameter is missing", 400

    if not is_valid_domain(target_url):
        return "Invalid URL: Domain not allowed", 400

    # In a real proxy, you would make a request to the target_url here.
    # For this example, we just return a success message.
    #  ***  DO NOT IMPLEMENT A REAL PROXY WITHOUT THOROUGH SECURITY REVIEW  ***
    return f"Proxying to {target_url} (This is a placeholder - no actual request is made)", 200

if __name__ == '__main__':
    # DO NOT USE THIS IN PRODUCTION.  Use a production-ready WSGI server like Gunicorn or uWSGI.
    # This is only for development purposes.
    app.run(debug=True, host='0.0.0.0', port=5000)

