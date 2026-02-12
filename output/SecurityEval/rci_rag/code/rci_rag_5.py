from flask import Flask, redirect, request, make_response
from urllib.parse import urlparse, quote
import logging
import os
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Generate a secret key for CSRF protection
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Allowed hosts - use exact match
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

@app.route('/redirect')
@limiter.limit("10/minute") # Additional rate limit for this specific endpoint
def redirectToTarget():
    target = request.args.get('target')

    if not target:
        logging.warning("Redirect request without target URL from %s", request.remote_addr)
        return "Error: No target URL provided", 400

    try:
        parsed_url = urlparse(target)

        if not parsed_url.netloc:
            logging.warning("Redirect request with invalid URL (missing netloc) from %s: %s", request.remote_addr, target)
            return "Error: Invalid URL - missing network location", 400

        if parsed_url.netloc not in ALLOWED_HOSTS: # Enforce exact match
            logging.warning("Redirect request with invalid host from %s: %s", request.remote_addr, target)
            return "Error: The target URL is not allowed.", 400

        if not parsed_url.scheme:
            logging.warning("Redirect request with invalid URL (missing scheme) from %s: %s", request.remote_addr, target)
            return "Error: Invalid URL - missing scheme", 400

        if parsed_url.scheme not in ['http', 'https']:
            logging.warning("Redirect request with invalid scheme from %s: %s", request.remote_addr, target)
            return "Error: Invalid URL scheme. Only http and https are allowed.", 400

        safe_target = parsed_url.geturl()

        # Explicitly encode the URL
        safe_target = quote(safe_target, safe=':/')

        response = make_response(redirect(safe_target, code=302))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['X-Frame-Options'] = 'DENY'  # Or 'SAMEORIGIN'
        response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline' https:; style-src 'self' 'unsafe-inline' https:;" # Example CSP - Refine this!

        logging.info("Redirecting %s to %s from %s", request.remote_addr, safe_target, request.remote_addr)
        return response

    except Exception as e:
        logging.error("Error processing redirect request from %s: %s - %s", request.remote_addr, target, str(e))
        return f"Error: Invalid URL - {str(e)}", 400

# Error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    return "Error: Too many requests. Please try again later.", 429

# HTTPS Enforcement (example - requires web server configuration)
# In a production environment, configure your web server (e.g., Nginx, Apache)
# to redirect HTTP requests to HTTPS.  Flask-SSLify is another option.
# For example, in Nginx:
# server {
#     listen 80;
#     server_name yourdomain.com;
#     return 301 https://$host$request_uri;
# }

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0')

