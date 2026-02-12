import os
import logging
import secrets
from markupsafe import Markup
from flask import Flask, request, make_response, redirect, url_for
from urllib.parse import urlparse
import re
import ssl
import certifi  # For trusted CA certificates
import unicodedata

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

# Configuration - Use environment variables
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS")
if not ALLOWED_DOMAINS:
    app.logger.critical("ALLOWED_DOMAINS environment variable not set! Exiting.")
    raise ValueError("ALLOWED_DOMAINS environment variable not set")
ALLOWED_DOMAINS = ALLOWED_DOMAINS.split(",")

TRUSTED_CERTIFICATE_AUTHORITIES = os.environ.get("TRUSTED_CERTIFICATE_AUTHORITIES", certifi.where())  # Use certifi by default

# Generate a secure secret key (never commit this to version control!)
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY")
if not app.config['SECRET_KEY']:
    app.logger.critical("FLASK_SECRET_KEY environment variable not set! Exiting.")
    raise ValueError("FLASK_SECRET_KEY environment variable not set")

# Regular expression for validating names (alphanumeric only, no spaces)
NAME_REGEX = r"^[a-zA-Z0-9]+$"
MAX_NAME_LENGTH = 50
PROHIBITED_NAMES = ["admin", "root", "administrator"]  # Example deny list

def is_valid_name(name):
    """
    Validates the name against a regular expression and a deny list.
    """
    if not isinstance(name, str):
        return False
    name = name.strip()  # Remove leading/trailing whitespace
    if len(name) > MAX_NAME_LENGTH:
        return False

    name = unicodedata.normalize('NFKC', name)  # Normalize Unicode

    if not bool(re.match(NAME_REGEX, name)):
        return False

    if name.lower() in [n.lower() for n in PROHIBITED_NAMES]:  # Case-insensitive check
        return False

    return True


def is_valid_url(url):
    """
    Validates a URL against a list of allowed domains.
    """
    try:
        result = urlparse(url)
        if not all([
            result.scheme == "https",  # Only allow https
            result.netloc in ALLOWED_DOMAINS  # Check against allowlist
        ]):
            return False

        # Example of path validation (very basic)
        if ".." in result.path:  # Prevent path traversal
            return False

        # Add more validation for path, query, and fragment as needed

        return True
    except:
        return False


def validate_ssl_certificate(hostname, port=443):
    """
    Validates the SSL/TLS certificate of a given hostname.
    This function checks if the certificate is valid and issued by a trusted CA.
    """
    try:
        context = ssl.create_default_context(cafile=TRUSTED_CERTIFICATE_AUTHORITIES)
        context.check_hostname = True  # Explicitly enable hostname verification
        context.verify_mode = ssl.CERT_REQUIRED

        with ssl.create_connection((hostname, port), context=context) as sock:
            sock.getpeercert()  # This will raise an exception if the certificate is invalid
        return True
    except ssl.SSLError as e:
        app.logger.error(f"SSL Certificate Validation Failed for {hostname}: {e}")
        return False
    except Exception as e:
        app.logger.error(f"Error during SSL validation for {hostname}: {e}")
        return False


@app.route('/showName')
def name():
    """
    Get "name" from the request, validate it,
    make a response with it, and return the response object
    """
    name = request.args.get('name')

    if not name:
        return "Name parameter is missing", 400

    if not is_valid_name(name):
        return "Invalid name format.  Only alphanumeric characters are allowed.", 400

    # Use Markup to escape the name if constructing HTML manually
    escaped_name = Markup.escape(name)
    response = make_response(f"Hello, {escaped_name}!")
    response.headers['Content-Type'] = 'text/plain'
    return response


#  Example of a safer redirect using a mapping
ALLOWED_REDIRECTS = {
    "home": url_for('home'),  # Assuming you have a route named 'home'
    "about": url_for('about') # Assuming you have a route named 'about'
}

@app.route('/redirect')
def redirect_url():
    """
    Redirects to a predefined internal URL based on a short code.
    """
    target = request.args.get('target')

    if not target:
        return "Target parameter is missing", 400

    if target not in ALLOWED_REDIRECTS:
        app.logger.warning(f"Attempted redirect to invalid target: {target}")
        return "Invalid redirect target", 400

    redirect_url = ALLOWED_REDIRECTS[target]
    app.logger.info(f"Redirecting to: {redirect_url}")
    return redirect(redirect_url, code=302)


if __name__ == '__main__':
    #  IMPORTANT:  In a production environment, use a proper WSGI server (e.g., Gunicorn, uWSGI)
    #  and configure HTTPS with a valid SSL/TLS certificate.
    #  This example runs in HTTP for demonstration purposes only.
    #  DO NOT USE ssl_context='adhoc' IN PRODUCTION!
    app.run(debug=True, host='0.0.0.0', port=5000) # Remove ssl_context for production

