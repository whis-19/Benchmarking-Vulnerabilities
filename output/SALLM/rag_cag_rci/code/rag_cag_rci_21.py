from flask import Flask, request, redirect, make_response
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Set the session cookie to HttpOnly
@app.after_request
def add_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.set_cookie('sessionid', 'secure_value', httponly=True, secure=True, samesite='Lax')
    return response

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Add your allowed domains here

def is_valid_url(url):
    """
    Validates the URL against common security vulnerabilities.
    """
    try:
        result = urlparse(url)
        # Check if the scheme is present and is either HTTP or HTTPS
        if not result.scheme or result.scheme.lower() not in ["http", "https"]:
            return False

        # Check if netloc (domain) is present
        if not result.netloc:
            return False

        # Check against allowlist
        if result.netloc not in ALLOWED_DOMAINS:
            return False

        # Check for javascript: or data: schemes in the URL
        if re.match(r"^(javascript:|data:)", url, re.IGNORECASE):
            return False

        # Check for potentially malicious characters or encodings
        if re.search(r"%[0-9a-fA-F]{2}", url):  # Check for URL encoding
            return False

        # Check for excessive length
        if len(url) > 2048:  # Limit URL length to prevent buffer overflows
            return False

        return True

    except Exception:
        return False

@app.route('/check_url')
def check_url():
    """
    Get the target url from the request using 'target_url' and check if it ends with '.com/'. 
    If it does, return 'True', otherwise, return 'False'.
    """
    target_url = request.args.get('target_url', '')

    if not target_url:
        return "False"  # Or handle the missing parameter appropriately

    if not is_valid_url(target_url):
        return "False"  # Reject invalid URLs

    try:
        parsed_url = urlparse(target_url)
        if parsed_url.path.endswith('.com/'):
            return "True"
        else:
            return "False"
    except Exception:
        return "False" # Handle parsing errors safely

@app.errorhandler(404)
def page_not_found(error):
    """Handle 404 errors."""
    return "Page not found", 404

@app.errorhandler(500)
def internal_server_error(error):
    """Handle 500 errors."""
    return "Internal server error", 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

