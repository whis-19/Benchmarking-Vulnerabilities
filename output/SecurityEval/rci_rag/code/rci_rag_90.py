from flask import request, redirect, Flask, session
from urllib.parse import urlparse
import secrets
import os
import logging
import re  # Import the regular expression module

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a strong secret key

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_HOSTS = ['example.com', 'www.example.com']  # Add your allowed hosts

# Session security settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF

# Rate limiting (example - needs a proper implementation with storage)
RATE_LIMIT = 10  # 10 requests per minute
REQUEST_COUNTS = {}  # Store request counts per IP address
import time

def is_rate_limited(ip_address):
    """
    Checks if the IP address has exceeded the rate limit.
    """
    now = time.time()
    if ip_address in REQUEST_COUNTS:
        requests, timestamp = REQUEST_COUNTS[ip_address]
        if now - timestamp < 60:  # Within the last minute
            if requests >= RATE_LIMIT:
                return True
            else:
                REQUEST_COUNTS[ip_address] = (requests + 1, timestamp)
                return False
        else:
            REQUEST_COUNTS[ip_address] = (1, now)  # Reset count
            return False
    else:
        REQUEST_COUNTS[ip_address] = (1, now)
        return False


@app.after_request
def add_header(response):
    """
    Set security headers for each response.
    """
    response.headers['Content-Type'] = 'text/html; charset=utf-8'  # Specify encoding
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    # Adjust Content-Security-Policy based on your application's needs.  Use a CSP generator.
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline';"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' # Only enable if HTTPS is fully enabled
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

def sanitize_url(url):
    """
    Sanitizes the URL to remove potentially harmful characters.
    This is an extra layer of defense against open redirect vulnerabilities.
    """
    # Remove control characters and invalid characters
    sanitized_url = re.sub(r'[\x00-\x1F\x7F-\xFF]', '', url)
    # Remove javascript: or data: protocols
    sanitized_url = re.sub(r'(?i)(javascript:|data:)', '', sanitized_url)
    return sanitized_url

@app.route('/flask_redirect', methods=['GET', 'POST'])
def flask_redirect():
    """
    Get the url from the request and redirect to it, with security checks.
    """
    ip_address = request.remote_addr
    if is_rate_limited(ip_address):
        logger.warning(f"Rate limit exceeded for IP: {ip_address}")
        return "Error: Rate limit exceeded", 429  # HTTP 429 Too Many Requests


    if request.method == 'POST':
        target = request.form.get('url')
        nonce = request.form.get('nonce')

        if not target:
            logger.warning(f"No URL provided in the request from IP: {ip_address}")
            return "Error: No URL provided", 400

        if not nonce or nonce != session.get('nonce'):
            logger.warning(f"Invalid nonce provided in the request from IP: {ip_address}")
            return "Error: Invalid nonce", 400

        try:
            # Sanitize the input URL
            target = sanitize_url(target)

            parsed_url = urlparse(target)
            
            if not parsed_url.scheme or parsed_url.scheme not in ALLOWED_SCHEMES:
                logger.warning(f"Invalid URL scheme: {parsed_url.scheme} from IP: {ip_address}")
                return "Error: Invalid URL scheme", 400

            if not parsed_url.netloc:
                logger.warning(f"Invalid URL host (empty netloc) from IP: {ip_address}")
                return "Error: Invalid URL host", 400

            # Check if the host is in the allowlist
            if parsed_url.netloc not in ALLOWED_HOSTS:
                logger.warning(f"Disallowed host: {parsed_url.netloc} from IP: {ip_address}")
                return "Error: Disallowed host", 400

            # Reconstruct the URL to prevent manipulation
            safe_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
            if parsed_url.query:
                safe_url += "?" + parsed_url.query
            if parsed_url.fragment:
                safe_url += "#" + parsed_url.fragment

            logger.info(f"Redirecting to: {safe_url} for IP: {ip_address}")
            return redirect(safe_url, code=302)

        except Exception as e:
            logger.error(f"Error parsing URL: {e} from IP: {ip_address}")
            return "Error: Invalid URL", 400

    # Generate a unique nonce for CSRF protection
    nonce = secrets.token_hex(16)
    session['nonce'] = nonce

    return f"""
    <form method="post">
        <label for="url">Enter URL:</label><br>
        <input type="text" id="url" name="url"><br><br>
        <input type="hidden" name="nonce" value="{nonce}">
        <input type="submit" value="Redirect">
    </form>
    """

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

