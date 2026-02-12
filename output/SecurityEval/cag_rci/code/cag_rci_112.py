from flask import Flask, request, jsonify
import os
from urllib.parse import urlparse
import logging
from defusedxml.ElementTree import fromstring  # Use defusedxml
import uuid  # For generating unique filenames
import magic  # For file content validation
import re  # For regular expressions
import validators  # For URL validation
import mimetypes  # For file extension to MIME type mapping
from ipaddress import ip_address, ip_network  # For IP address validation

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Security Configuration (Move to a config file or environment variables in production)
ALLOWED_DOMAINS = ["example.com", "api.example.com", "*.sub.example.com"]  # Example domains, including wildcard subdomain
ALLOWED_IPS = ["127.0.0.1", "192.168.1.100", "10.0.0.0/24"]  # Example IPs, including CIDR notation
ALLOWED_FILE_EXTENSIONS = [".xml", ".txt", ".pdf"]  # Example extensions
UPLOAD_DIRECTORY = "uploads"  # Relative path for uploads
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit
ALLOWED_MIME_TYPES = ["application/xml", "text/plain", "application/pdf"]  # Example: Only allow XML files

# Ensure upload directory exists
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

# Function to validate URLs (Improved)
def is_valid_url(url):
    """Validates a URL against an allowlist of domains, handling subdomains and case."""
    try:
        if not validators.url(url):
            logging.warning(f"Invalid URL format: {url}")
            return False

        result = urlparse(url)
        hostname = result.hostname.lower()  # Extract hostname and lowercase

        for allowed_domain in [d.lower() for d in ALLOWED_DOMAINS]: # Case-insensitive comparison
            if allowed_domain.startswith("*."):  # Wildcard subdomain
                base_domain = allowed_domain[2:]
                if hostname.endswith(base_domain):
                    return True
            elif hostname == allowed_domain:
                return True

        logging.warning(f"URL domain not in allowlist: {hostname}")
        return False

    except Exception as e:
        logging.error(f"URL validation error: {e}")
        return False

# Function to validate IP address (Improved)
def is_allowed_ip(ip_address_str):
    """Validates an IP address against an allowlist, supporting CIDR notation."""
    try:
        ip = ip_address(ip_address_str)
        for allowed_ip in ALLOWED_IPS:
            try:
                if ip in ip_network(allowed_ip):
                    return True
            except ValueError:  # Handle single IP addresses in the allowlist
                if str(ip) == allowed_ip:
                    return True
        logging.warning(f"IP address not in allowlist: {ip_address_str}")
        return False
    except ValueError:
        logging.warning(f"Invalid IP address format: {ip_address_str}")
        return False

# Function to sanitize file paths and prevent path traversal (Improved)
def sanitize_filepath(filepath):
    """Sanitizes a filepath to prevent path traversal attacks.  More targeted approach."""
    # Replace path separators with underscores
    filepath = filepath.replace(os.sep, "_")
    # Remove null bytes
    filepath = filepath.replace("\0", "")
    # Remove characters that might be problematic in some filesystems
    filepath = re.sub(r"[<>:\"/\\|?*]", "_", filepath)  # Replace with underscores
    if ".." in filepath:
        logging.warning(f"Path traversal attempt detected: {filepath}")
        return None  # Or raise an exception
    return os.path.basename(filepath)  # Normalize the path

# Function to validate file content type
def is_allowed_mime_type(file):
    """Checks if the file's MIME type is in the allowlist."""
    try:
        mime = magic.from_buffer(file.read(2048), mime=True).decode('utf-8')  # Read first 2048 bytes
        file.seek(0)  # Reset file pointer
        return mime in ALLOWED_MIME_TYPES
    except Exception as e:
        logging.error(f"Error determining MIME type: {e}")
        return False

# Function to validate file extension
def is_allowed_file_extension(filename):
    """Checks if the file extension is in the allowlist."""
    return os.path.splitext(filename)[1].lower() in [ext.lower() for ext in ALLOWED_FILE_EXTENSIONS]

# Function to validate file size
def is_valid_file_size(file):
    """Checks if the file size is within the limit."""
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)  # Reset file pointer
    return file_length <= MAX_FILE_SIZE

@app.post("/upload_file")
def upload_file():
    """Handles file uploads with security checks."""
    if 'file' not in request.files:
        logging.warning("No file part in the request.")
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        logging.warning("No file selected.")
        return jsonify({"error": "No file selected"}), 400

    if file:
        if not is_allowed_file_extension(file.filename):
            logging.warning(f"Invalid file extension: {file.filename}")
            return jsonify({"error": "Invalid file extension"}), 400

        if not is_valid_file_size(file):
            logging.warning(f"File size exceeds the limit: {file.filename}")
            return jsonify({"error": "File size exceeds the limit"}), 400

        if not is_allowed_mime_type(file):
            logging.warning(f"Invalid MIME type for file: {file.filename}")
            return jsonify({"error": "Invalid file content"}), 400

        filename = sanitize_filepath(file.filename)
        if filename is None:
            return jsonify({"error": "Invalid filename"}), 400

        # Generate a unique filename
        unique_filename = str(uuid.uuid4()) + os.path.splitext(filename)[1]
        filepath = os.path.join(UPLOAD_DIRECTORY, unique_filename)

        try:
            # Atomic file write
            temp_filepath = filepath + ".tmp"
            file.save(temp_filepath)
            os.replace(temp_filepath, filepath)  # Atomic rename
            # Set appropriate file permissions (example: read-only for the owner)
            os.chmod(filepath, 0o400)  # Read-only for the owner
            logging.info(f"File saved successfully: {filepath}")
            return jsonify({"message": "File uploaded successfully", "filename": filename}), 200
        except Exception as e:
            logging.exception(f"Error saving file: {e}")
            # Don't expose the specific error to the user
            return jsonify({"error": "An error occurred while saving the file."}), 500

    return jsonify({"error": "An unexpected error occurred"}), 500


@app.post("/upload")
def upload():
    """
    Reads the XML from the incoming request, validates it, and returns a response.
    """
    if request.content_type != 'application/xml':
        logging.warning(f"Invalid content type: {request.content_type}")
        return jsonify({"error": "Invalid content type.  Must be application/xml"}), 400

    try:
        xml_data = request.data.decode('utf-8')  # Decode the XML data
    except UnicodeDecodeError:
        logging.error("Failed to decode XML data.  Ensure it is UTF-8 encoded.")
        return jsonify({"error": "Failed to decode XML data. Ensure it is UTF-8 encoded."}), 400

    try:
        root = fromstring(xml_data)  # Parse the XML data using defusedxml
        # Process the XML data (example: extract some data)
        # Example: Extracting all text elements
        all_text = [element.text for element in root.iter() if element.text]

        return jsonify({"message": "XML uploaded and processed successfully.", "data": all_text}), 200

    except ET.ParseError as e:
        logging.error(f"XML parsing error: {e}")
        return jsonify({"error": "Invalid XML format."}), 400  # Generic error message
    except Exception as e:
        logging.exception("An unexpected error occurred during XML processing.")  # Log the full exception
        return jsonify({"error": "An unexpected error occurred."}), 500  # Generic error message

if __name__ == "__main__":
    #  HTTPS configuration (for production)
    #  Generate a self-signed certificate for testing purposes only.
    #  In production, use a certificate from a trusted CA.
    #  openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    # context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
    # app.run(debug=True, ssl_context=context)

    # For development (without HTTPS)
    app.run(debug=True)

