import requests
from urllib.parse import urlparse
import ssl
import secrets
import os
from flask import Flask, request, make_response, render_template, redirect, url_for, session
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key for session management

# --- Security Configuration ---

ALLOWED_DOMAINS = ["semmle.com"]  # Whitelist of allowed domains
CSRF_COOKIE_NAME = 'csrf_token'
REFERER_CHECK_ENABLED = True  # Enable/disable Referer header check

# --- Helper Functions ---

def is_valid_url(url):
    """
    Validates the URL and checks if the domain is in the allowlist.
    """
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc, result.path]) and result.netloc in ALLOWED_DOMAINS
    except:
        return False

def make_https_request(url):
    """
    Makes an HTTPS request with SSL/TLS certificate validation.
    """
    try:
        if not is_valid_url(url):
            print(f"Error: Invalid or disallowed URL: {url}")
            return None

        if not url.startswith("https://"):
            print("Warning: Enforcing HTTPS for security.")
            url = url.replace("http://", "https://")  # Enforce HTTPS

        response = requests.get(url, verify=True)  # Verify SSL/TLS certificate
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return None

def generate_csrf_token():
    """Generates a cryptographically secure CSRF token."""
    return secrets.token_urlsafe(32)

def set_csrf_cookie(response):
    """Sets the CSRF cookie with a cryptographically strong pseudorandom value."""
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token  # Store in session for double-submit cookie
    response.set_cookie(CSRF_COOKIE_NAME, csrf_token, httponly=True, secure=True, samesite='Strict') # Secure, HttpOnly, and Strict SameSite
    return response

def verify_csrf_token(request):
    """Verifies the CSRF token using the double-submitted cookie method."""
    cookie_csrf_token = request.cookies.get(CSRF_COOKIE_NAME)
    session_csrf_token = session.get('csrf_token')

    if not cookie_csrf_token or not session_csrf_token or cookie_csrf_token != session_csrf_token:
        print("CSRF token verification failed.")
        return False
    return True

def verify_referer(request):
    """Verifies the origin page of the request by checking the HTTP Referer header."""
    if not REFERER_CHECK_ENABLED:
        return True

    referer = request.headers.get('Referer')
    if not referer:
        print("Referer header is missing.")
        return False

    #  Strict allowlist for Referer domains.  Adjust as needed.
    allowed_referer_domains = ["yourdomain.com", "127.0.0.1"] # Example: Replace with your actual domain(s)
    try:
        referer_domain = urlparse(referer).netloc
        if referer_domain not in allowed_referer_domains:
            print(f"Invalid Referer domain: {referer_domain}")
            return False
    except:
        print("Error parsing Referer header.")
        return False

    return True

def sanitize_input(input_string, allowed_chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"):
    """Sanitizes input by allowing only characters in the allowlist."""
    return ''.join(c for c in input_string if c in allowed_chars)

# --- Example Usage (Flask Application) ---

@app.route('/')
def index():
    """Renders a form with CSRF protection."""
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return render_template('form.html', csrf_token=csrf_token)

@app.route('/submit', methods=['POST'])
def submit():
    """Handles form submission with CSRF and Referer verification."""
    if not verify_csrf_token(request):
        return "CSRF verification failed.", 400

    if not verify_referer(request):
        return "Referer verification failed.", 403

    # Validate and sanitize input data
    user_input = request.form.get('user_input', '')
    sanitized_input = sanitize_input(user_input)

    # Process the sanitized input (e.g., store in database, etc.)
    print(f"Received and processed input: {sanitized_input}")

    return "Form submitted successfully!"

@app.route('/external_request')
def external_request():
    """Makes a request to an external website (semmle.com)."""
    target_url = "https://semmle.com"
    response = make_https_request(target_url)

    if response:
        return f"Request to {target_url} successful. Status code: {response.status_code}"
    else:
        return f"Request to {target_url} failed."

@app.route('/state_change', methods=['GET'])
def state_change():
    """Example of a GET request that triggers a state change (use with caution)."""
    #  Important:  GET requests should ideally be idempotent (not change state).
    #  If you *must* use GET for a state change, ensure it's well-protected.

    if not verify_referer(request):
        return "Referer verification failed.", 403

    # Perform the state change operation here (e.g., delete something, update a value)
    #  Add appropriate authorization checks before performing the action.
    print("State change operation performed (example).")

    return "State change operation completed (example)."

@app.route('/set_cookie')
def set_cookie_route():
    """Sets a secure cookie."""
    resp = make_response("Cookie set!")
    resp = set_csrf_cookie(resp)
    return resp

@app.route('/xss_example')
def xss_example():
    """Demonstrates how to prevent XSS attacks."""
    user_provided_data = request.args.get('data', '')

    # Escape the user-provided data to prevent XSS
    escaped_data = escape(user_provided_data)

    # Use the escaped data in the template
    return render_template('xss_example.html', data=escaped_data)

@app.route('/redirect_example')
def redirect_example():
    """Demonstrates a safe redirect."""
    # Validate the redirect URL against an allowlist
    redirect_url = request.args.get('url')
    if redirect_url and is_valid_url(redirect_url):
        return redirect(redirect_url)
    else:
        return "Invalid redirect URL."

# --- Templates (example - create these in a 'templates' folder) ---

# templates/form.html
#

