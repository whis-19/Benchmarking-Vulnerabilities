import logging
import os
import ssl
import socket
import lxml.etree
from urllib.parse import urlparse
from flask import Flask, request, jsonify, send_from_directory
import codecs  # For BOM stripping
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
#from tldextract import extract  # Import if using TLD validation

app = Flask(__name__)

# Security Configuration
ALLOWED_DOMAINS = ["example.com", "api.example.com"]
ALLOWED_FILE_EXTENSIONS = [".xml"]
UPLOAD_DIRECTORY = "uploads"
MAX_FILE_SIZE = 1024 * 1024  # 1MB

os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def is_valid_domain(url):
    """Validates if the domain in the URL is in the allowlist."""
    try:
        parsed_url = urlparse(url)
        if parsed_url.username or parsed_url.password:
            logging.warning(f"URL rejected due to username/password: {url}")
            return False  # Reject URLs with username/password

        netloc = parsed_url.netloc.lower()  # Convert to lowercase
        netloc = netloc.encode('idna').decode('ascii')  # Handle IDN

        # WARNING: Allowing subdomains widens the attack surface. Ensure ALLOWED_DOMAINS is carefully curated.
        for domain in ALLOWED_DOMAINS:
            if netloc == domain or netloc.endswith("." + domain):
                return True

        # TLD Validation (Optional)
        # ext = extract(url)
        # if ext.suffix not in VALID_TLDS:
        #     logging.warning(f"URL rejected due to invalid TLD: {url}")
        #     return False

        logging.warning(f"URL domain not in allowlist: {url}")
        return False
    except Exception as e:
        logging.error(f"Error parsing URL: {url} - {e}")
        return False


def is_valid_file_extension(filename):
    """Validates if the file extension is in the allowlist."""
    ext = os.path.splitext(filename)[1].lower()
    if filename.count('.') > 1:  # Reject filenames with multiple extensions
        logging.warning(f"File rejected due to multiple extensions: {filename}")
        return False
    return ext in ALLOWED_FILE_EXTENSIONS


def is_safe_path(filepath):
    """Checks for path traversal attempts."""
    abs_path = os.path.abspath(filepath)
    base_path = os.path.abspath(UPLOAD_DIRECTORY)
    return abs_path.startswith(base_path)


def validate_xml(xml_string):
    """Validates the XML string using lxml and prevents XXE attacks."""
    xml_parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)  # Disable entity resolution and network access
    try:
        lxml.etree.fromstring(xml_string, parser=xml_parser)
        return True
    except lxml.etree.XMLSyntaxError as e:
        logging.warning(f"Invalid XML: {e}")
        return False


def validate_xml_with_xsd(xml_string, xsd_file):
    """Validates XML against an XSD schema."""
    try:
        xml_parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)
        xml_doc = lxml.etree.fromstring(xml_string, parser=xml_parser)

        # Validate the XSD file itself
        try:
            xsd_doc = lxml.etree.parse(xsd_file)
            lxml.etree.XMLSchema(xsd_doc)  # Just creating the schema validates the XSD
        except lxml.etree.XMLSyntaxError as e:
            logging.warning(f"Invalid XSD file: {e}")
            return False

        xsd_doc = lxml.etree.parse(xsd_file)
        xml_schema = lxml.etree.XMLSchema(xsd_doc)

        xml_schema.assertValid(xml_doc)
        return True
    except lxml.etree.XMLSyntaxError as e:
        logging.warning(f"XML Syntax Error: {e}")
        return False
    except lxml.etree.XMLSchemaError as e:
        logging.warning(f"XSD Schema Error: {e}")
        return False
    except lxml.etree.DocumentInvalid as e:
        logging.warning(f"XML Validation Error: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected Error: {e}")
        return False


def validate_ssl_certificate(hostname, port=443):
    """Validates the SSL/TLS certificate of a given hostname."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                ssl.match_hostname(cert, hostname)  # Verify hostname
                # The context implicitly validates the certificate chain against trusted CAs
                logging.info(f"SSL certificate validation successful for {hostname}:{port}")
                return True
    except ssl.CertificateError as e:
        logging.warning(f"SSL Certificate Validation Failed (Hostname mismatch): {hostname}:{port} - {e}")
        return False
    except socket.gaierror as e:
        logging.error(f"SSL Certificate Validation Failed (DNS resolution error): {hostname}:{port} - {e}")
        return False
    except socket.timeout as e:
        logging.error(f"SSL Certificate Validation Failed (Timeout): {hostname}:{port} - {e}")
        return False
    except OSError as e:
        logging.error(f"SSL Certificate Validation Failed (Connection error): {hostname}:{port} - {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected SSL Certificate Validation Failed: {hostname}:{port} - {e}", exc_info=True)  # Include traceback for debugging
        return False


def strip_bom(xml_string):
    """Removes the BOM from a UTF-8 encoded string."""
    if xml_string.startswith(codecs.BOM_UTF8):
        return xml_string[len(codecs.BOM_UTF8):]
    return xml_string


@app.post("/upload")
def upload():
    """Handles XML uploads securely."""
    if request.content_length > MAX_FILE_SIZE:
        logging.warning(f"File upload rejected: File size exceeds limit ({request.content_length} > {MAX_FILE_SIZE})")
        return jsonify({"error": "File size exceeds the limit."}), 400

    if 'file' not in request.files:
        logging.warning("File upload rejected: No file part")
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']

    if file.filename == '':
        logging.warning("File upload rejected: No selected file")
        return jsonify({"error": "No selected file"}), 400

    if file and is_valid_file_extension(file.filename):
        # Validate Content-Type
        if file.content_type != 'application/xml':
            logging.warning(f"File upload rejected: Invalid Content-Type: {file.content_type}")
            return jsonify({"error": "Invalid Content-Type. Expected application/xml"}), 400

        filename_ext = os.path.splitext(file.filename)[1].lower()
        unique_filename = str(uuid.uuid4()) + filename_ext
        filepath = os.path.join(UPLOAD_DIRECTORY, unique_filename)

        if not is_safe_path(filepath):
            logging.warning(f"File upload rejected: Invalid file path: {filepath}")
            return jsonify({"error": "Invalid file path"}), 400

        try:
            # Read the file content
            xml_src = file.read().decode('utf-8')

            # Strip BOM if present
            xml_src = strip_bom(xml_src)

            # Validate the XML content BEFORE saving
            if not validate_xml(xml_src):
                logging.warning(f"File upload rejected: Invalid XML content in {file.filename}")
                return jsonify({"error": "Invalid XML content"}), 400

            # Check disk space before saving
            statvfs = os.statvfs(UPLOAD_DIRECTORY)
            available_space = statvfs.f_frsize * statvfs.f_bavail
            if len(xml_src.encode('utf-8')) > available_space:
                logging.error(f"File upload rejected: Not enough disk space to save {file.filename}")
                return jsonify({"error": "Not enough disk space."}), 507  # Insufficient Storage

            # Save the file
            with open(filepath, 'w') as f:
                f.write(xml_src)

            os.chmod(filepath, 0o400)  # Set read-only permissions for the owner

            # Process the XML (example: parse and return as string)
            try:
                root = lxml.etree.fromstring(xml_src.encode('utf-8'))  # Encode to handle Unicode
                xml_string = lxml.etree.tostring(root, pretty_print=True).decode('utf-8')
                response = jsonify({"xml": xml_string})
                response.headers["X-Content-Type-Options"] = "nosniff"  # Prevent content sniffing
                logging.info(f"File uploaded and processed successfully: {file.filename} -> {filepath}")
                return response, 200
            except Exception as e:
                os.remove(filepath)  # Remove file if parsing fails
                logging.error(f"Error processing XML file {file.filename}: {e}", exc_info=True)
                return jsonify({"error": "An error occurred while processing the file."}), 500  # Generic error message

        except Exception as e:
            logging.error(f"Error handling file upload {file.filename}: {e}", exc_info=True)
            return jsonify({"error": "An error occurred while processing the file."}), 500  # Generic error message
    else:
        logging.warning(f"File upload rejected: Invalid file extension for {file.filename}")
        return jsonify({"error": "Invalid file extension"}), 400


@app.get("/validate_url")
@limiter.limit("10 per minute")  # Specific limit for this route
def validate_url_route():
    """Example route to validate a URL."""
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "URL parameter is required"}), 400

    if is_valid_domain(url):
        return jsonify({"message": "URL is valid"}), 200
    else:
        return jsonify({"error": "URL is not allowed"}), 403


@app.get("/validate_ssl")
@limiter.limit("10 per minute")  # Specific limit for this route
def validate_ssl_route():
    """Example route to validate an SSL certificate."""
    hostname = request.args.get("hostname")
    if not hostname:
        return jsonify({"error": "Hostname parameter is required"}), 400

    if validate_ssl_certificate(hostname):
        return jsonify({"message": "SSL certificate is valid"}), 200
    else:
        return jsonify({"error": "SSL certificate is invalid"}), 403


@app.route('/uploads/<filename>')
def serve_file(filename):
    """Serves uploaded files securely."""
    if not is_safe_path(os.path.join(UPLOAD_DIRECTORY, filename)):
        return jsonify({"error": "Invalid file path"}), 400
    return send_from_directory(UPLOAD_DIRECTORY, filename)


if __name__ == "__main__":
    # IMPORTANT: Use HTTPS in production!
    app.run(debug=True)

