import re
import secrets
import urllib.parse
from flask import Flask, request, redirect, make_response, session, abort
import logging
import time
import redis  # Import the redis library

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ALLOWED_HOSTS (Example using a whitelist - more secure)
ALLOWED_HOSTS = ["example.com", "www.example.com", "sub.example.com"]

# Redis Configuration (for rate limiting)
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True) # Added decode_responses

RATE_LIMIT = 10  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

@app.before_request
def before_request():
    """Set HttpOnly flag for session cookie and specify encoding."""
    session.permanent = True
    session.modified = True

@app.route('/')
def index():
    return "Welcome!  Use /redirect?target=<url> to redirect."

@app.route('/redirect')
def redirect_route():
    target = request.args.get('target')

    if not target:
        logging.warning("Target parameter is missing.")
        return "Target parameter is missing.", 400

    try:
        parsed_url = urllib.parse.urlparse(target)

        if not parsed_url.scheme or parsed_url.scheme not in ('http', 'https'):
            logging.warning(f"Invalid scheme: {parsed_url.scheme}")
            return "Invalid scheme.", 400

        if not parsed_url.hostname:
            logging.warning("Hostname is missing.")
            return "Hostname is missing.", 400

        # Whitelist check (more secure than regex)
        if parsed_url.hostname not in ALLOWED_HOSTS:
            logging.warning(f"Target URL {target} not in allowed hosts.")
            return "Invalid hostname.", 400

        validated_url = urllib.parse.urljoin(request.url_root, parsed_url.path)

        # Delay the redirect with a warning (example)
        # return f"Are you sure you want to redirect to: <a href='{validated_url}'>{validated_url}</a>"

        response = make_response(redirect(validated_url, code=302))
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
        response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; style-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        return response

    except Exception as e:
        logging.error(f"An error occurred: {e}", exc_info=True)
        return "An error occurred.", 500  # Internal Server Error

@app.before_request
def rate_limit():
    client_ip = request.remote_addr
    key = f"rate_limit:{client_ip}"

    # Get the current request count and expiration time from Redis
    count = redis_client.get(key)
    if count is None:
        count = 0
        redis_client.setex(key, RATE_LIMIT_WINDOW, 0)  # Set initial count and expiration
    else:
        count = int(count)

    if count >= RATE_LIMIT:
        logging.warning(f"Rate limit exceeded for IP: {client_ip}")
        abort(429, "Rate limit exceeded. Please try again later.")

    # Increment the request count
    redis_client.incr(key)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

