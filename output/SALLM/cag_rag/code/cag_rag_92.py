from flask import Flask, request, make_response, render_template_string
import logging
import os
import secrets
from urllib.parse import urlparse

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Set a strong secret key for CSRF protection

ALLOWED_DOMAINS = ['example.com', 'localhost']  # Example allowlist

def is_safe_url(target):
    """
    Checks if a URL is safe to redirect to.  This prevents open redirects.
    """
    try:
        ref_url = urlparse(request.host_url)
        test_url = urlparse(target)
        return test_url.scheme in ('http', 'https') and \
               ref_url.netloc == test_url.netloc
    except:
        return False

def is_allowed_domain(url):
    """
    Checks if the domain of a URL is in the allowlist.
    """
    try:
        domain = urlparse(url).netloc
        return domain in ALLOWED_DOMAINS
    except:
        return False

@app.route('/logging', methods=['GET', 'POST'])
def logdata():
    """
    Get the name from the request using 'name' key and log it.
    Implements CSRF protection using double-submit cookie method.
    Prevents XSS by escaping the name.
    Validates and sanitizes the name input.
    """
    if request.method == 'GET':
        # Generate CSRF token and set it in a cookie
        csrf_token = secrets.token_hex(16)
        resp = make_response(render_template_string("""
            <form method="POST">
                <label for="name">Enter your name:</label>
                <input type="text" id="name" name="name">
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <button type="submit">Submit</button>
            </form>
        """, csrf_token=csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
        return resp

    elif request.method == 'POST':
        name = request.form.get('name', '')
        csrf_token = request.form.get('csrf_token')
        cookie_csrf_token = request.cookies.get('csrf_token')

        # CSRF protection: Verify CSRF token
        if not csrf_token or not cookie_csrf_token or csrf_token != cookie_csrf_token:
            logging.warning("CSRF token mismatch or missing.")
            return "CSRF token validation failed.", 400

        # Input validation and sanitization (example: prevent XSS)
        if not name:
            logging.warning("Name is empty.")
            return "Name cannot be empty.", 400

        # Basic sanitization: HTML escape (more robust solutions like bleach are recommended)
        name = escape_html(name)

        # Logging the sanitized name
        logging.info(f"Received name: {name}")

        return f"Hello, {name}!"

    else:
        return "Method not allowed", 405

def escape_html(text):
    """
    Basic HTML escaping to prevent XSS.  Use a more robust library like 'bleach' for production.
    """
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    text = text.replace('"', '&quot;')
    text = text.replace("'", '&#39;')
    return text

@app.route('/redirect')
def redirect_url():
    """
    Example of handling redirects safely.
    """
    target = request.args.get('next')
    if not target:
        return "No redirect target provided.", 400

    if is_safe_url(target) and is_allowed_domain(target):
        return f"Redirecting to {target}" # In a real app, use redirect(target)
    else:
        return "Unsafe redirect target.", 400

if __name__ == '__main__':
    # Use HTTPS in production.  This example is for development only.
    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Get a real certificate for production.

