import os
import subprocess
import re
from urllib.parse import urlparse, quote
from flask import Flask, request, abort, send_file
import ssl  # Import the ssl module
import mimetypes
import logging
import tempfile
import magic  # For MIME type detection (install with `pip install python-magic`)
import ipaddress # For IP address validation
import shutil

app = Flask(__name__)

# Security Configuration - Adjust these based on your needs
ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Whitelist of allowed domains
ALLOWED_FILE_EXTENSIONS = {
    ".txt": "text/plain",
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    # Add more as needed
}
UPLOAD_DIRECTORY = "/var/www/myapp/downloads"  # Secure directory for downloads
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit
MAX_FILENAME_LENGTH = 255

# Dynamically generate the domain regex
DOMAIN_REGEX = re.compile(r'(' + '|'.join([re.escape(d) for d in ALLOWED_DOMAINS]) + r')$')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Ensure the upload directory exists and has appropriate permissions
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)
os.chmod(UPLOAD_DIRECTORY, 0o700)  # Restrict access to the owner

def is_valid_url(url):
    """
    Validates the URL format and checks against the allowlist.
    """
    try:
        result = urlparse(url)
        # More robust check, also prevents user info in URL
        if not all([result.scheme in ['http', 'https'], result.netloc, result.path]):
            return False
        if result.username or result.password:
            return False # Prevent embedded credentials

        try:
            ipaddress.ip_address(result.netloc)
            return False  # Reject URLs with IP addresses
        except ValueError:
            pass  # Not an IP address, continue checking

        # Add more checks here if needed, e.g., for invalid characters in path
        return True
    except:
        return False

def is_allowed_domain(url):
    """
    Checks if the domain of the URL is in the allowlist.
    Allows subdomains using a regex.
    """
    try:
        domain = urlparse(url).netloc
        # Check for subdomain match using regex
        if DOMAIN_REGEX.match(domain): # Use the regex
            return True
        return False
    except ValueError:  # Catch URL parsing errors
        return False
    except Exception as e:
        logging.error(f"Unexpected error in is_allowed_domain: {e}")
        return False

def sanitize_filename(filename):
    """
    Sanitizes the filename to prevent path traversal and other attacks.
    """
    # Replace any characters that are not alphanumeric, underscores, or dots with underscores
    filename = re.sub(r"[^a-zA-Z0-9_.]", "_", filename)
    # Remove any sequences of ".."
    filename = filename.replace("..", "")
    # Ensure the filename doesn't start with a dot
    filename = filename.lstrip(".")
    # Limit filename length
    filename = filename[:MAX_FILENAME_LENGTH]
    # Lowercase the filename
    filename = filename.lower()
    # Remove leading/trailing whitespace
    filename = filename.strip()
    return filename

def check_disk_space(path, required_space):
    """Checks if there is enough free disk space at the given path."""
    total, used, free = shutil.disk_usage(path)
    return free >= required_space

def download_file(url, filename):
    """
    Downloads the file from the given URL using subprocess and performs security checks.
    """
    # Use a temporary directory for downloading
    with tempfile.TemporaryDirectory(dir=UPLOAD_DIRECTORY) as temp_dir:
        filepath = os.path.join(temp_dir, filename)

        try:
            # Use subprocess with a timeout to prevent indefinite hanging
            # and to limit resource consumption.  Also, disable shell=True
            # for security.
            command = ["curl", "-s", "-f", "--location", "--connect-timeout", "10", "--max-time", "60", "--max-filesize", str(MAX_FILE_SIZE // 1024), url, "-o", filepath] # Size in KB
            logging.info(f"Executing command: {' '.join(command)}") # Log the command
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                error_message = stderr.decode().strip()
                if "Could not resolve host" in error_message:
                    error_message = "Error: Could not resolve host.  Invalid domain name."
                elif "Connection timed out" in error_message:
                    error_message = "Error: Connection timed out."
                elif "Maximum file size exceeded" in error_message:  # Example - check for this in stderr
                    error_message = "Error: Maximum file size exceeded (server-side limit)."
                logging.error(f"Error downloading file from {url}: {error_message}")
                raise Exception(f"Download failed: {error_message}")

            # Check file size after download (redundant, but good to have)
            file_size = os.path.getsize(filepath)
            if file_size > MAX_FILE_SIZE:
                os.remove(filepath)  # Remove the oversized file
                raise ValueError("File size exceeds the maximum allowed size.")

            # Check MIME type
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(filepath)
            logging.info(f"Detected MIME type: {mime_type}")

            # Validate MIME type against allowed extensions
            ext = os.path.splitext(filename)[1].lower()
            if ext in ALLOWED_FILE_EXTENSIONS and ALLOWED_FILE_EXTENSIONS[ext] != mime_type:
                os.remove(filepath)
                raise ValueError(f"MIME type ({mime_type}) does not match file extension ({ext}).")

            # Move the file to the final destination
            final_filepath = os.path.join(UPLOAD_DIRECTORY, filename)
            os.replace(filepath, final_filepath) # Atomic move

            return final_filepath, mime_type  # Return both filepath and mime_type

        except Exception as e:
            # Clean up any partially downloaded files
            if os.path.exists(filepath):
                os.remove(filepath)
            logging.exception(f"Error downloading file from {url}: {e}")
            raise e


@app.route('/curl')
def curl():
    """
    Get the url from the request using 'url'.
    Download the file by taking the url parameter from the request.
    :return: url
    """
    url = request.args.get('url')

    if not url:
        logging.warning("Missing URL parameter in request.")
        return "Error: URL parameter is missing.", 400

    if not is_valid_url(url):
        logging.warning(f"Invalid URL format: {url}")
        return "Error: Invalid URL format.", 400

    if not is_allowed_domain(url):
        logging.warning(f"URL domain not allowed: {url}")
        return "Error: URL domain is not allowed.", 403

    # Extract filename from URL (more robust method)
    try:
        filename = os.path.basename(urlparse(url).path)
        if not filename:
            filename = "downloaded_file"  # Default filename if URL doesn't have one
    except:
        filename = "downloaded_file"

    filename = sanitize_filename(filename)

    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_FILE_EXTENSIONS:
        logging.warning(f"File extension not allowed: {filename}")
        return "Error: File extension not allowed.", 400

    try:
        # Check disk space before downloading
        if not check_disk_space(UPLOAD_DIRECTORY, MAX_FILE_SIZE * 2):  # Allow some headroom
            logging.error("Not enough disk space to download file.")
            return "Error: Not enough disk space.", 507  # HTTP 507 Insufficient Storage

        url = quote(url, safe=':/')  # Encode the URL, preserving the scheme and slashes
        filepath, mime_type = download_file(url, filename)

        # Securely serve the file
        return send_file(filepath, as_attachment=True, download_name=filename, mimetype=mime_type)

    except ValueError as e:
        logging.warning(f"Value error during download: {e}")
        return f"Error: {e}", 400
    except Exception as e:
        logging.exception(f"Unexpected error during download from {url}: {e}") # Log the error for debugging
        return "Error: An unexpected error occurred during download.", 500


if __name__ == '__main__':
    # Use HTTPS in production
    # app.run(debug=True, ssl_context='adhoc')  # For development only - generates a self-signed certificate
    # For production, use a proper SSL certificate:
    # app.run(debug=False, ssl_context=('path/to/cert.pem', 'path/to/key.pem'))
    app.run(debug=True) # For local testing without HTTPS

