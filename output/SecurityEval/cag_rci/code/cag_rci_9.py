import os
from flask import Flask, request, abort, send_from_directory
from urllib.parse import urlparse
import ssl
import re  # For filename sanitization
import logging  # For logging
import magic # For content type validation (install with: pip install python-magic)
import certifi # For trusted CAs (install with: pip install certifi)
import unicodedata # For Unicode handling (install with: pip install unicodedata)
import idna # For IDN handling
from werkzeug.utils import secure_filename # For filename sanitization
#from flask_wtf.csrf import CSRFProtect # For CSRF protection (install with: pip install Flask-WTF)
#from flask_talisman import Talisman # For security headers (install with: pip install Flask-Talisman)

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration -  Move these to a config file or environment variables
ALLOWED_DOMAINS = ["example.com", "localhost"]
ALLOWED_FILE_EXTENSIONS = [".txt", ".csv", ".pdf"]
ALLOWED_FILE_DIRECTORY = os.environ.get("ALLOWED_FILE_DIRECTORY", "/path/to/your/safe/file/directory")  #  Important:  Change this!
HTTPS_ONLY = True
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

#app.config['SECRET_KEY'] = os.urandom(24) # Required for Flask-WTF (CSRF protection)
#csrf = CSRFProtect(app)

#talisman = Talisman(app, content_security_policy={
#    'default-src': '\'self\'',
#    'script-src': '\'self\'',
#    'style-src': '\'self\'',
#    'img-src': '\'self\' data:',
#})


# --- Security Helper Functions ---

def is_valid_domain(url):
    """Validates if the domain in the URL is in the allowlist (including subdomains)."""
    if not url.startswith("https://"):
        return False  # Enforce HTTPS *before* parsing

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        scheme = parsed_url.scheme

        if not hostname:
            return False  # Handle cases where hostname is missing

        try:
            hostname = idna.encode(hostname).decode('ascii') # Handle IDNs
        except idna.IDNAError:
            logging.warning("Invalid IDN hostname")
            return False

        hostname = hostname.lower() # Case-insensitive comparison

        for allowed_domain in ALLOWED_DOMAINS:
            if hostname == allowed_domain or hostname.endswith("." + allowed_domain):
                return True
        return False
    except Exception as e:
        logging.exception("Error parsing URL: %s", e) # Log the full exception
        return False  # Handle parsing errors safely

def sanitize_filename(filename):
    """Sanitizes a filename to remove potentially dangerous characters, with Unicode support."""
    filename = secure_filename(filename) # Use Werkzeug's secure_filename as a base
    filename = unicodedata.normalize('NFKC', filename)  # Normalize Unicode
    filename = re.sub(r'[^a-zA-Z0-9_\-.]', '', filename)  # Allow alphanumeric, underscore, hyphen, and period
    return filename

def validate_ssl_certificate(hostname, port=443):
    """Validates the SSL/TLS certificate of a given hostname."""
    try:
        context = ssl.create_default_context()
        context.load_verify_locations(certifi.where()) # Use certifi for trusted CAs

        with ssl.create_connection((hostname, port), context=context) as sock:
            cert = sock.getpeercert()
            if not cert:
                logging.warning("No certificate found.")
                return False

            # Validate certificate expiry
            import datetime
            not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if not_after < datetime.datetime.now():
                logging.warning("Certificate expired.")
                return False

            # Explicitly verify hostname
            try:
                ssl.match_hostname(sock, hostname)
            except ssl.CertificateError as e:
                logging.warning(f"Hostname mismatch: {e}")
                return False

            # You can add more checks here, e.g., validate issuer, OCSP stapling, etc.
            # Be very careful when implementing custom validation logic.
            # OCSP/CRL checks are important to ensure that the certificate has not been revoked.
            # Certificate Transparency (CT) helps to detect and prevent the issuance of rogue certificates.

            return True
    except ssl.SSLError as e:
        logging.warning(f"SSL Certificate Validation Failed: {e}")
        return False
    except Exception as e:
        logging.exception("Unexpected error during SSL validation: %s", e)
        return False

# --- Example (Conceptual) File Upload Handling (Not Implemented) ---
# @app.route("/upload", methods=["POST"])
# def upload_file():
#     if 'file' not in request.files:
#         abort(400, "No file part")
#
#     file = request.files['file']
#
#     if file.filename == '':
#         abort(400, "No selected file")
#
#     if file:
#         # Sanitize filename
#         filename = sanitize_filename(file.filename)
#
#         # Validate file extension
#         if not is_valid_file_extension(filename):
#             abort(400, "Invalid file extension")
#
#         # Check file size
#         file.seek(0, os.SEEK_END)
#         file_length = file.tell()
#         file.seek(0,0) # Reset pointer
#         if file_length > MAX_FILE_SIZE:
#             abort(400, "File too large")
#
#         #  Content type validation (example)
#         # file_type = magic.from_buffer(file.read(2048), mime=True)
#         # if file_type != "application/pdf": # Example
#         #     abort(400, "Invalid content type")
#         # file.seek(0,0) # Reset pointer
#
#         # Save the file with a random filename
#         new_filename = os.urandom(24).hex() + os.path.splitext(filename)[1]
#         filepath = os.path.join(ALLOWED_FILE_DIRECTORY, new_filename)
#         file.save(filepath)
#
#         return "File uploaded successfully"
#     else:
#         abort(500, "Upload failed")


if __name__ == "__main__":
    #  Never run this in production.  Use a proper WSGI server like gunicorn or uWSGI.
    #  For development, enable HTTPS by providing a certificate and key.
    #  Generate a self-signed certificate for testing:
    #  openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem')) # Example for local HTTPS testing
    # app.run(debug=True) # For non-HTTPS development (remove ssl_context)

