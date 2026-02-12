import os
import re
import logging
from flask import Flask, request, jsonify
from dotenv import load_dotenv
import bcrypt
from functools import wraps
import time
from werkzeug.exceptions import TooManyRequests
from flask import make_response
# from flask_limiter import Limiter  # Uncomment if using Flask-Limiter
# from flask_limiter.util import get_remote_address # Uncomment if using Flask-Limiter
import sys  # For exiting the application

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load environment variables from .env file
load_dotenv()

# Securely store username and password (using environment variables)
# NEVER hardcode credentials directly in the code.
USERNAME = os.environ.get("USERNAME", None)
PASSWORD_HASH = os.environ.get("PASSWORD_HASH", None)

# Ensure environment variables are set
if not USERNAME or not PASSWORD_HASH:
    logging.error("USERNAME and PASSWORD_HASH environment variables must be set.")
    print("Error: USERNAME and PASSWORD_HASH environment variables must be set.")
    sys.exit(1)  # Exit the application

# --- Rate Limiting ---
RATE_LIMIT = 10  # 10 requests per minute
RATE_LIMIT_WINDOW = 60  # seconds
request_counts = {}  # Store request counts per IP address

def rate_limit(limit=RATE_LIMIT, per=RATE_LIMIT_WINDOW):
    """Rate limiting decorator."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip_address = request.remote_addr
            now = time.time()

            if ip_address not in request_counts:
                request_counts[ip_address] = []

            # Remove requests older than the rate limit window
            request_counts[ip_address] = [ts for ts in request_counts[ip_address] if ts > now - per]

            if len(request_counts[ip_address]) >= limit:
                logging.warning(f"Rate limit exceeded for IP: {ip_address}")
                raise TooManyRequests("Too many requests. Please try again later.")

            request_counts[ip_address].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# --- Password Verification using bcrypt ---
def verify_password(password, stored_hash):
    """Verifies a password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))

# --- Route ---
@app.route('/check_mod', methods=['POST'])
@rate_limit()
def check_mod():
    """
    Checks if the username and password provided in the request body are correct.
    Returns 'true' if correct, otherwise returns 'false'.
    """
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            logging.warning(f"Missing username or password from IP: {request.remote_addr}")
            return jsonify({'result': 'false', 'message': 'Username and password are required.'}), 400

        # Input Validation
        if not isinstance(username, str) or not isinstance(password, str):
            logging.warning(f"Invalid username or password type from IP: {request.remote_addr}")
            return jsonify({'result': 'false', 'message': 'Username and password must be strings.'}), 400

        if len(username) > 50 or len(password) > 50:
            logging.warning(f"Username or password too long from IP: {request.remote_addr}")
            return jsonify({'result': 'false', 'message': 'Username and password too long.'}), 400

        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            logging.warning(f"Invalid username format from IP: {request.remote_addr}")
            return jsonify({'result': 'false', 'message': 'Invalid username format.'}), 400

        if username == USERNAME and verify_password(password, PASSWORD_HASH):
            logging.info(f"Successful authentication for user: {username} from IP: {request.remote_addr}")
            return jsonify({'result': 'true'}), 200
        else:
            logging.warning(f"Failed authentication attempt for user: {username} from IP: {request.remote_addr}")
            return jsonify({'result': 'false', 'message': 'Authentication failed.'}), 401

    except (TypeError, ValueError) as e:
        logging.error(f"Invalid JSON data from IP: {request.remote_addr}: {e}")
        return jsonify({'result': 'false', 'message': 'Invalid JSON data.'}), 400
    except TooManyRequests as e:
        logging.warning(f"Rate limit exceeded for IP: {request.remote_addr}")
        return jsonify({'result': 'false', 'message': str(e)}), 429

# --- Error Handling ---
@app.errorhandler(TooManyRequests)
def handle_too_many_requests(e):
    logging.warning(f"Rate limit exceeded: {e}")
    return jsonify({'result': 'false', 'message': 'Too many requests. Please try again later.'}), 429

# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response

if __name__ == '__main__':
    # NEVER use debug=True in production. It exposes sensitive information.
    app.run(debug=False, host='0.0.0.0', port=5000)

