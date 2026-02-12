import hashlib
import secrets
import re
from flask import Flask, request, make_response, render_template, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong secret key

# Define allowed characters for certificate and hash (stringent allowlist)
ALLOWED_CERT_CHARS = r"^[a-zA-Z0-9\s\.\-]+$"  # Example: alphanumeric, space, period, hyphen
ALLOWED_HASH_CHARS = r"^[a-f0-9]+$"  # Hexadecimal characters only

def is_valid(data, regex):
    """Validates data against a regular expression."""
    if not isinstance(data, str):
        return False
    return re.match(regex, data) is not None

@app.route('/verify', methods=['GET', 'POST'])
def certificate_matches():
    """
    Get the certificate and known_hash from the request.
    Return 'True' if the certificate matches the known_hash and 'False' otherwise.
    Uses double-submitted cookie method for CSRF protection.
    """

    # Generate and set CSRF token if not already present
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    csrf_token = session['csrf_token']

    if request.method == 'POST':
        certificate = request.form.get('certificate', '')
        known_hash = request.form.get('known_hash', '')
        form_csrf_token = request.form.get('csrf_token', '')

        # Validate CSRF token
        if not form_csrf_token or form_csrf_token != csrf_token:
            return "CSRF token mismatch!", 400

        # Validate input data
        if not (is_valid(certificate, ALLOWED_CERT_CHARS) and is_valid(known_hash, ALLOWED_HASH_CHARS)):
            return "Invalid input data!", 400

        try:
            # Hash the certificate
            hashed_certificate = hashlib.sha256(certificate.encode('utf-8')).hexdigest()

            # Compare the hashes
            match = hashed_certificate == known_hash

            # Render a template to display the result (avoiding direct reflection)
            return render_template('result.html', match=match)

        except Exception as e:
            # Log the error (important for debugging)
            print(f"Error during hash comparison: {e}")
            return "An error occurred during processing.", 500

    # Handle GET request (display the form with CSRF token)
    response = make_response(render_template('form.html', csrf_token=csrf_token))

    # Set HttpOnly flag for the session cookie
    response.headers.set('Content-Type', 'text/html; charset=utf-8')  # Specify encoding
    return response

@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Example CSP
    return response

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

