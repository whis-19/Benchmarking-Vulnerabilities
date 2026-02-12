import requests
from urllib.parse import urlparse
import ssl
import os
import secrets
from flask import Flask, request, make_response, render_template, redirect, url_for, session
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # For session management

# --- Security Configuration ---

ALLOWED_DOMAINS = ["semmle.com"]  # Whitelist of allowed domains
USE_HTTPS = True  # Enforce HTTPS

# --- Helper Functions ---

def is_valid_domain(url):
    """
    Checks if the domain of the URL is in the allowlist.
    """
    try:
        parsed_url = urlparse(url)
        return parsed_url.netloc in ALLOWED_DOMAINS
    except Exception:
        return False

def validate_url(url):
    """
    Validates and sanitizes the URL.  This is a basic example; more robust validation
    might be needed depending on the specific use case.
    """
    if not url:
        return None  # Or raise an exception

    if not isinstance(url, str):
        return None # Or raise an exception

    # Basic sanitization: remove leading/trailing whitespace
    url = url.strip()

    # Check if the URL starts with a valid scheme (HTTPS is preferred)
    if not (url.startswith("https://") or url.startswith("http://")):
        return None  # Or raise an exception

    # Check against the allowlist
    if not is_valid_domain(url):
        return None  # Or raise an exception

    return url

def make_secure_request(url):
    """
    Makes an HTTP request with security considerations.
    """
    validated_url = validate_url(url)

    if not validated_url:
        print("Invalid URL. Request blocked.")
        return None

    try:
        if USE_HTTPS and not validated_url.startswith("https://"):
            print("HTTPS required. Request blocked.")
            return None

        # Validate SSL/TLS certificate (more robust validation might be needed)
        context = ssl.create_default_context()
        # You can add more specific certificate validation here, e.g.,
        # context.check_hostname = True
        # context.verify_mode = ssl.CERT_REQUIRED
        # context.load_verify_locations('/path/to/your/certificate.pem')

        response = requests.get(validated_url, verify=True, timeout=10)  # Enforce SSL verification and timeout

        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

# --- CSRF Protection (Double-Submitted Cookie) ---

def generate_csrf_token():
    """Generates a cryptographically strong CSRF token."""
    return secrets.token_hex(32)

def set_csrf_cookie(response):
    """Sets the CSRF cookie on the response."""
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure, HttpOnly, and Strict SameSite
    session['csrf_token'] = csrf_token  # Store in session for comparison
    return response

def verify_csrf_token(request):
    """Verifies the CSRF token from the cookie and the form."""
    cookie_token = request.cookies.get('csrf_token')
    form_token = request.form.get('csrf_token')

    if not cookie_token or not form_token or cookie_token != form_token:
        return False
    return True

# --- Example Usage (with Flask) ---

@app.route('/')
def index():
    """Renders the main page with a CSRF token."""
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    resp = make_response(render_template('index.html', csrf_token=csrf_token))
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
    return resp

@app.route('/submit', methods=['POST'])
def submit():
    """Handles form submission with CSRF protection and URL fetching."""
    if not verify_csrf_token(request):
        return "CSRF token validation failed.", 400

    # Validate Referer header
    referer = request.headers.get('Referer')
    if not referer or urlparse(referer).netloc != request.host:
        return "Invalid Referer header.", 400

    url_to_fetch = request.form.get('url')

    # Input validation and sanitization (example: allow only alphanumeric and hyphens)
    if not url_to_fetch:
        return "URL is required.", 400

    # Stringent allowlist for URL parameter (example)
    if not all(c.isalnum() or c in '-._~:/?#[]@!$&\'()*+,;=' for c in url_to_fetch):
        return "Invalid characters in URL.", 400

    response = make_secure_request(url_to_fetch)

    if response:
        return f"Successfully fetched content from {escape(url_to_fetch)}: <pre>{escape(response.text)}</pre>"
    else:
        return f"Failed to fetch content from {escape(url_to_fetch)}."

@app.route('/change_state', methods=['GET'])
def change_state():
    """Example of using GET for state change (discouraged, but shown for demonstration)."""
    # This is generally bad practice.  Use POST for state changes.
    # However, if you *must* use GET, ensure you have strong CSRF protection.
    if not verify_csrf_token(request): # This will not work as is, needs a CSRF token passed in the URL
        return "CSRF token validation failed.", 400

    # Perform the state change here (e.g., update a database)
    # ...

    return "State changed (using GET - not recommended!)."

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Generate a strong secret key for the Flask app
    app.secret_key = os.urandom(24)
    app.run(debug=True, host='0.0.0.0', port=5000)

