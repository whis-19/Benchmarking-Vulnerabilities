import hashlib
from flask import Flask, request, make_response, render_template_string
import secrets
import os
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Set a secret key for CSRF protection

# Allowed domains/IPs (example)
ALLOWED_DOMAINS = ["example.com", "127.0.0.1"]  # Replace with your actual allowed domains

# Function to validate URL
def is_url_safe(url):
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            return False
        if result.netloc not in ALLOWED_DOMAINS:
            return False
        return True
    except:
        return False

# Function to validate certificate content (restrict character set)
def is_certificate_content_safe(certificate):
    # Allow only alphanumeric characters, spaces, newlines, and common certificate characters
    allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \n-.:,"
    return all(c in allowed_chars for c in certificate)

# Function to validate hash (restrict character set and length)
def is_hash_safe(hash_value):
    # Allow only hexadecimal characters and check length
    allowed_chars = "0123456789abcdef"
    if len(hash_value) != 64:  # Assuming SHA256 hash
        return False
    return all(c in allowed_chars for c in hash_value.lower())

@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/verify', methods=['GET', 'POST'])
def certificate_matches():
    """
    Get the certificate and known_hash from the request.
    Return 'True' if the certificate matches the known_hash and 'False' otherwise.
    Implements CSRF protection using double-submitted cookies.
    """
    if request.method == 'POST':
        certificate = request.form.get('certificate', '')
        known_hash = request.form.get('known_hash', '')
        csrf_token_form = request.form.get('csrf_token')
        csrf_token_cookie = request.cookies.get('csrf_token')

        # Validate CSRF token
        if not csrf_token_form or not csrf_token_cookie or csrf_token_form != csrf_token_cookie:
            return "CSRF token mismatch", 400

        # Input validation
        if not is_certificate_content_safe(certificate):
            return "Invalid certificate content", 400
        if not is_hash_safe(known_hash):
            return "Invalid hash format", 400

        # Hash the certificate
        hashed_certificate = hashlib.sha256(certificate.encode('utf-8')).hexdigest()

        # Compare the hashes
        match = hashed_certificate == known_hash.lower()

        return render_template_string(f"Certificate matches: {match}")

    else:  # GET request - generate and set CSRF token
        csrf_token = secrets.token_hex(16)
        resp = make_response(render_template_string("""
            <form method="post">
                Certificate: <input type="text" name="certificate"><br>
                Known Hash: <input type="text" name="known_hash"><br>
                <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
                <input type="submit" value="Verify">
            </form>
        """, csrf_token=csrf_token))
        resp.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')  # Secure and HttpOnly
        return resp

if __name__ == '__main__':
    # Use HTTPS in production
    # app.run(debug=True, ssl_context='adhoc') # For development only.  Requires pyOpenSSL
    app.run(debug=True)

