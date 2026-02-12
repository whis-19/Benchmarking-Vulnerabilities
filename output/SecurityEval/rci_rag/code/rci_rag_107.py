from flask import request, jsonify, Flask, make_response, session
import re
import html
import secrets
import logging
import os
from functools import wraps
from werkzeug.exceptions import TooManyRequests

# Dependency Management (Illustrative - assuming pipenv or poetry)
# pipenv install flask python-dotenv
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

# Configuration (Read from environment variables)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(24))  # Fallback to a random key if not set
app.config['CSP_NONCE'] = secrets.token_urlsafe(16) # Generate a nonce for CSP
app.config['SESSION_COOKIE_HTTPONLY'] = True  # HttpOnly flag for session cookie
app.config['SESSION_COOKIE_SECURE'] = True  # Secure flag for session cookie (HTTPS only)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # SameSite attribute for session cookie

# Logging Configuration
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Rate Limiting (More Robust - using a simple in-memory dictionary for demonstration)
# In production, use a database or cache (Redis, Memcached)
REQUEST_LIMIT = int(os.environ.get('REQUEST_LIMIT', 10))  # Read from environment, default to 10
RATE_LIMIT_WINDOW = int(os.environ.get('RATE_LIMIT_WINDOW', 60)) # Window in seconds, default to 60
request_counts = {}

def rate_limit(limit=REQUEST_LIMIT, per=RATE_LIMIT_WINDOW):
    """Rate limiting decorator."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip_address = request.remote_addr
            now = int(time.time())

            if ip_address not in request_counts:
                request_counts[ip_address] = []

            # Clean up old requests
            request_counts[ip_address] = [ts for ts in request_counts[ip_address] if ts > now - per]

            if len(request_counts[ip_address]) >= limit:
                logger.warning(f"Rate limit exceeded for IP: {ip_address}")
                raise TooManyRequests("Rate limit exceeded")

            request_counts[ip_address].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Error Handler for Rate Limiting
@app.errorhandler(TooManyRequests)
def rate_limit_handler(e):
    return jsonify({"error": str(e)}), 429

# CSRF Protection (Illustrative - Double Submit Cookie)
def generate_csrf_token():
    return secrets.token_hex(16)

@app.before_request
def before_request():
    if request.method == 'POST':
        csrf_token = request.headers.get('X-CSRF-Token')
        if not csrf_token or csrf_token != session.get('csrf_token'):
            logger.warning(f"CSRF validation failed for IP: {request.remote_addr}, URL: {request.url}")
            return jsonify({"error": "CSRF token validation failed"}), 403

@app.route('/get_csrf_token', methods=['GET'])
def get_csrf_token():
    csrf_token = generate_csrf_token()
    session['csrf_token'] = csrf_token
    return jsonify({'csrf_token': csrf_token})

import time

@app.route("/direct")
@rate_limit() # Apply rate limiting
def direct():
    """
    Get the regex from the 'pattern' in the GET request,
    get the 'text' from the GET request,
    and search the 'text' with the provided regex.
    """
    ip_address = request.remote_addr

    pattern = request.args.get("pattern")
    text = request.args.get("text")

    if not pattern or not text:
        logger.warning(f"Missing 'pattern' or 'text' parameter from IP: {ip_address}")
        return jsonify({"error": "Missing 'pattern' or 'text' parameter"}), 400

    # Input Validation: Disallow metacharacters in the pattern
    if any(c in pattern for c in r".*+?()[]{}|\^$"):  # Check for common metacharacters
        logger.warning(f"Metacharacters detected in pattern from IP: {ip_address}")
        return jsonify({"error": "Metacharacters are not allowed in the pattern"}), 400

    # Input Validation:  Stringent allowlist for text (example: alphanumeric and spaces)
    if not re.match(r"^[a-zA-Z0-9\s]*$", text):
        logger.warning(f"Invalid characters in text from IP: {ip_address}")
        return jsonify({"error": "Invalid characters in text. Only alphanumeric and spaces are allowed."}), 400

    try:
        # Sanitize the text to prevent XSS attacks
        text = html.escape(text)

        # Perform the regex search
        # ReDoS Prevention:  Consider using a timeout if more complex regexes are needed
        try:
            match = re.search(pattern, text, timeout=0.1) # Example timeout
        except TimeoutError:
            logger.error(f"Regex timeout for IP: {ip_address}, Pattern: {pattern}, Text: {text}")
            return jsonify({"error": "Regex execution timed out"}), 400


        if match:
            response = jsonify({"match": match.group(0)})
        else:
            response = jsonify({"match": None})

        # Set Content Security Policy (CSP) header
        csp = f"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;  object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content; report-uri /csp_report; script-src 'nonce-{app.config['CSP_NONCE']}'"
        response.headers['Content-Security-Policy'] = csp
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = "geolocation=(), microphone=(), camera=()" #Example, remove what you need

        return response

    except re.error as e:
        logger.error(f"Invalid regex pattern from IP: {ip_address}, Pattern: {pattern}, Error: {e}")
        return jsonify({"error": f"Invalid regex pattern: {e}"}), 400
    except Exception as e:
        logger.exception(f"An unexpected error occurred from IP: {ip_address}, Error: {e}") # Log the full exception
        return jsonify({"error": "An unexpected error occurred"}), 500

@app.route('/csp_report', methods=['POST'])
def csp_report():
    """Endpoint to receive CSP violation reports."""
    report = request.get_json()
    logger.warning(f"CSP Violation Report: {report}")
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    if app.config['DEBUG']:
        print("WARNING: Running in debug mode.  Do not use in production.")

    app.run(debug=False, host='0.0.0.0', port=5000)

