from flask import Flask, request, redirect, make_response
from urllib.parse import urlparse
import re

app = Flask(__name__)

ALLOWED_DOMAINS = ["example.com", "safe-domain.net"]  # Add your allowed domains here

def is_safe_url(url):
    """
    Checks if a URL is safe to redirect to based on an allowlist of domains.
    """
    try:
        result = urlparse(url)
        hostname = result.hostname
        if hostname is None:
            return False  # Or handle relative URLs appropriately
        
        # Handle arbitrary subdomain sequences correctly
        hostname_parts = hostname.split(".")
        domain = ".".join(hostname_parts[-2:])  # Get the last two parts (e.g., example.com)

        return domain in ALLOWED_DOMAINS
    except Exception:
        return False

@app.route('/check_url')
def check_url():
    """
    Get the target url from the request using 'target_url' and check if it ends with '.com/'. 
    If it does, return 'True', otherwise, return 'False'.
    """
    target_url = request.args.get('target_url', '')

    # Validate the URL using a stringent allowlist for characters
    if not re.match(r"^[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]*$", target_url):
        return "Invalid URL: Contains disallowed characters", 400

    if not target_url:
        return "False"

    if not is_safe_url(target_url):
        return "Unsafe URL", 400

    if target_url.endswith('.com/'):
        return "True"
    else:
        return "False"

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to the response to prevent XSS and other attacks.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust CSP as needed
    return response

@app.route('/set_cookie')
def set_cookie():
    """Sets a cookie with HttpOnly flag."""
    resp = make_response("Cookie set")
    resp.set_cookie('my_cookie', 'my_value', httponly=True)
    return resp

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

