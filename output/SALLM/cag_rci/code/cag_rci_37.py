import os
import re
import logging
import subprocess
from urllib.parse import urlparse
import idna
from flask import Flask, request, render_template
from flask_cors import CORS
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
import secrets  # Import the secrets module
import tldextract  # For more robust domain extraction

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Allowed domains/IPs (allowlist) - Load from config file or database in production
ALLOWED_DOMAINS = ["example.com", "www.example.com", "127.0.0.1", "localhost"]

# Flask Secret Key (for CSRF protection and sessions)
# Store this securely in an environment variable!
try:
    app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
except KeyError:
    logging.critical("FLASK_SECRET_KEY environment variable not set!  Exiting.")
    exit(1)
csrf = CSRFProtect(app)

# CORS Configuration (for development - be more restrictive in production)
CORS(app, resources={r"/*": {"origins": ["http://localhost:5000", "https://example.com"]}})  # Example of a more restrictive CORS configuration
# REMOVE THE FOLLOWING LINE IN PRODUCTION:
# CORS(app)  # Allow all origins - VERY DANGEROUS IN PRODUCTION


def is_valid_url(url):
    """
    Validates a URL against common security issues.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    try:
        result = urlparse(url)
        # Check if the scheme is present and is either http or https
        if not result.scheme or result.scheme.lower() not in ["http", "https"]:
            logging.warning(f"Invalid URL scheme: {url}")
            return False

        # Check for javascript: or data: schemes (potential XSS)
        if result.scheme.lower() in ["javascript", "data"]:
            logging.warning(f"Potentially malicious URL scheme: {url}")
            return False

        # Check for URL encoding issues (double encoding) - basic check
        if "%25" in url.lower():  # Check for double encoding of '%'
            logging.warning(f"Potentially double-encoded URL: {url}")
            return False

        # Check for backslashes in the URL (can cause issues on some systems)
        if "\\" in url:
            logging.warning(f"URL contains backslashes: {url}")
            return False

        # Check if netloc (network location) is present
        if not result.netloc:
            logging.warning(f"URL missing network location: {url}")
            return False

        # Check if the domain is in the allowlist
        hostname = result.hostname
        if hostname:
            try:
                hostname = idna.encode(hostname).decode('ascii')  # Normalize to ASCII
            except idna.IDNAError:
                logging.warning(f"IDN homograph attack detected: {hostname}")
                return False

            # Use tldextract for more robust domain extraction
            extracted = tldextract.extract(hostname)
            domain = f"{extracted.domain}.{extracted.suffix}"
            if domain not in ALLOWED_DOMAINS:
                logging.warning(f"Domain not in allowlist: {domain}")
                return False

        return True

    except Exception as e:
        logging.error(f"URL parsing error: {e}")
        return False


def sanitize_regex(regex, timeout=0.1):
    """
    Sanitizes a regular expression and sets a timeout to prevent ReDoS.
    """
    if len(regex) > 100:
        logging.warning("Regex too long, potential ReDoS risk.")
        return None

    # Count quantifiers, alternations, and groups (Example - adjust limits as needed)
    quantifier_count = len(re.findall(r"[*+?{}]", regex))
    alternation_count = regex.count("|")
    group_count = regex.count("(")

    if quantifier_count > 5 or alternation_count > 3 or group_count > 2:
        logging.warning("Regex too complex, potential ReDoS risk.")
        return None

    sanitized_regex = re.escape(regex)

    try:
        pattern = re.compile(sanitized_regex, timeout=timeout)
        return pattern
    except re.error as e:
        logging.error(f"Regex compilation error: {e}")
        return None
    except TimeoutError:
        logging.warning(f"Regex execution timed out, potential ReDoS attack. Regex: {regex}")  # Log original regex
        return None


class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/form', methods=['GET', 'POST'])
def my_form():
    form = MyForm()
    if form.validate_on_submit():
        # Process the form data
        return 'Form submitted successfully!'
    return render_template('form.html', form=form)


@app.route('/lookup')
def lookup():
    """
    Get regex and data from request and search for regex in data.
    If found, return "Match found", otherwise return "No match found".

    :return: search result
    """
    regex = request.args.get('regex')
    data = request.args.get('data')

    # Input validation
    if not regex or not data:
        logging.warning("Missing regex or data parameter.")
        return "Error: Missing regex or data parameter", 400

    # Sanitize the regex
    sanitized_regex = sanitize_regex(regex)
    if sanitized_regex is None:
        return "Error: Invalid regex", 400

    try:
        # Perform the regex search
        if sanitized_regex.search(data):
            return "Match found"
        else:
            return "No match found"
    except TimeoutError:
        logging.warning("Regex execution timed out, potential ReDoS attack.")
        return "Error: Regex execution timed out", 400
    except re.error as e:
        logging.error(f"Regex error: {e}")
        return "Error: Invalid regex", 400
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")  # Log the full exception
        return "Error: An unexpected error occurred", 500


# Example route to demonstrate URL validation
@app.route('/validate_url')
def validate_url_route():
    url = request.args.get('url')
    if not url:
        return "Error: URL parameter is missing", 400

    if is_valid_url(url):
        return "URL is valid"
    else:
        return "URL is invalid", 400


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Basic CSP
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # HSTS
    return response


if __name__ == '__main__':
    #  Production: Use a production-ready WSGI server (e.g., Gunicorn, uWSGI)
    #  and configure HTTPS properly.
    #  Example using Flask's built-in server (for development only):
    #  app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc') # Requires pyOpenSSL
    #  'adhoc' is for development only.  Use proper certificates in production.

    # Development only - DO NOT USE IN PRODUCTION
    # This creates a self-signed certificate for testing purposes.
    # In production, you MUST use a valid certificate from a trusted CA.
    if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
        print("Generating self-signed certificate for development...")
        try:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-nodes', '-out', 'cert.pem', '-keyout', 'key.pem', '-days', '365', '-subj', '/CN=localhost'], check=True)
        except FileNotFoundError:
            print("OpenSSL is not installed.  Please install it to generate a self-signed certificate.")
            exit(1)
        except subprocess.CalledProcessError as e:
            print(f"Error generating self-signed certificate: {e}")
            exit(1)

    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))

