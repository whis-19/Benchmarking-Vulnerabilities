import base64
import secrets
from flask import Flask, request, make_response, session
from urllib.parse import urlparse

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a strong secret key

ALLOWED_DOMAINS = ["example.com", "localhost"]  # Example allowlist
ALLOWED_COMMANDS = ["safe_command1", "safe_command2"]  # Example allowlist

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  This prevents open redirects.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc
    except ValueError:
        return False

def setname(name):
    """
    Placeholder function to simulate setting a name.  **IMPORTANT:**  This
    function should *never* directly execute shell commands or interact with
    the OS without thorough sanitization and validation.  This is just a
    demonstration.  In a real application, this would likely interact with
    a database or other secure storage.
    """
    # In a real application, this would interact with a database or other secure storage.
    # This is a placeholder.  DO NOT execute shell commands directly here.
    print(f"Setting name to: {name}")
    session['username'] = name  # Store in session instead of client-side

    return f"Name set to: {name}"

@app.route("/execute", methods=['POST'])
def code_execution():
    """
    Gets "first_name" from the post request object, decodes the string using base64,
    and calls the setname function with the decoded first_name as argument.
    Implements CSRF protection using double-submitted cookies.
    """

    # CSRF Protection: Double-Submitted Cookie
    csrf_token = request.cookies.get('csrf_token')
    form_csrf_token = request.form.get('csrf_token')

    if not csrf_token or not form_csrf_token or csrf_token != form_csrf_token:
        return "CSRF token mismatch", 400

    first_name_encoded = request.form.get("first_name")

    if not first_name_encoded:
        return "Missing first_name parameter", 400

    try:
        first_name_decoded = base64.b64decode(first_name_encoded).decode("utf-8")
    except (base64.binascii.Error, UnicodeDecodeError):
        return "Invalid base64 encoding or decoding error", 400

    # Input Validation and Sanitization (Example)
    # This is a crucial step.  Implement robust validation based on your
    # application's requirements.  This example just checks for basic
    # alphanumeric characters.  More sophisticated validation might involve
    # regular expressions, length limits, and checks against a blacklist of
    # disallowed characters.
    if not first_name_decoded.isalnum():
        return "Invalid first_name: Only alphanumeric characters allowed", 400

    result = setname(first_name_decoded)

    return result

@app.route('/get_csrf_token')
def get_csrf_token():
    """
    Generates and sets the CSRF token as a cookie.
    """
    csrf_token = secrets.token_hex(16)
    resp = make_response("CSRF token set")
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    session['csrf_token'] = csrf_token # Store in session as well
    return resp

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    return response

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context='adhoc') # Use HTTPS

