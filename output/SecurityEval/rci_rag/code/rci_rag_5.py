from flask import Flask, redirect, request, session, render_template_string, render_template
import re
import os
import secrets
from urllib.parse import urlparse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sslify import SSLify  # Import Flask-SSLify
import tldextract  # Import tldextract

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a cryptographically strong secret key

# Initialize Flask-SSLify
if 'DYNO' in os.environ:  # Check if running on Heroku (or similar)
    sslify = SSLify(app)

# Allowed domains using tldextract
ALLOWED_DOMAINS = ["example.com", "example.net"]

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Example rate limits
    storage_uri="redis://localhost:6379"  # Use an appropriate storage (e.g., Redis) for production
)


def is_safe_url(target):
    """
    Checks if the target URL is safe to redirect to.

    Args:
        target: The URL to redirect to.

    Returns:
        True if the URL is safe, False otherwise.
    """
    try:
        parsed_url = urlparse(target)
        # Check if the scheme is safe (http or https)
        if parsed_url.scheme not in ("http", "https"):
            return False

        # Use tldextract to get the domain
        extracted = tldextract.extract(target)
        domain = ".".join(extracted[1:])  # Join domain and suffix

        if domain not in ALLOWED_DOMAINS:
            return False

        return True
    except Exception:
        app.logger.exception("Error parsing URL: %s", target)  # Log the error
        return False  # Handle parsing errors as unsafe


@app.route('/redirect', methods=['GET', 'POST'])  # Allow POST requests
@limiter.limit("10/minute")  # Rate limit the redirect endpoint
def redirectToTarget():
    """
    Get target URL from request, check if it is a valid target,
    then redirect to the target URL.  Uses double-submitted cookie method.
    """
    if request.method == 'POST':
        target = request.form.get('target')
    else:
        target = request.args.get('target') # Consider removing GET support

    # Verify the CSRF token (double-submitted cookie)
    csrf_token = request.cookies.get('csrf_token')
    if not csrf_token or session.get('csrf_token') != csrf_token:
        app.logger.warning("CSRF token validation failed for target: %s", target)  # Log CSRF failures
        return "CSRF token validation failed.", 400

    if target and is_safe_url(target):
        # Intermediate redirect page
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Redirect Confirmation</title>
            </head>
            <body>
                <p>You are about to be redirected to: <b>{{ target|e }}</b></p>
                <p>Do you want to continue?</p>
                <p><b>Warning:</b> We are not responsible for the content of the target URL.</p>
                <a href="{{ target|e }}">Yes, continue</a> | <a href="/">No, go back</a>
            </body>
            </html>
            """, target=target)
    else:
        app.logger.warning("Invalid or unsafe URL: %s", target)  # Log invalid URLs
        return "The URL you entered is not allowed.", 400  # More specific error


@app.route('/get_csrf')
@limiter.limit("20/minute")  # Rate limit the CSRF token generation endpoint
def get_csrf():
    """
    Generates and sets a CSRF token in both a cookie and the session.
    """
    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token
    resp = app.make_response("CSRF token set")
    resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure cookie
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # HSTS
    return resp


@app.route('/')
def index():
    """
    Simple index page with a form to demonstrate CSRF protection.
    """
    return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirect Example</title>
        </head>
        <body>
            <h1>Redirect Example</h1>
            <form action="/redirect" method="POST">  <!-- Changed to POST -->
                <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">
                <label for="target">Target URL:</label>
                <input type="text" id="target" name="target" placeholder="Enter URL">
                <button type="submit">Redirect</button>
            </form>
            <p>Get a new CSRF token: <a href="/get_csrf">Get CSRF Token</a></p>
        </body>
        </html>
        """)


@app.errorhandler(429)
def ratelimit_handler(e):
    """
    Handles rate limit errors.
    """
    app.logger.warning("Rate limit exceeded: %s", request.remote_addr)
    return "Rate limit exceeded", 429


# Example Content Security Policy (CSP) - Adapt to your needs!
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    return response

if __name__ == '__main__':
    # Never run with debug=True in production!
    import logging
    logging.basicConfig(level=logging.INFO)  # Configure logging

    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

