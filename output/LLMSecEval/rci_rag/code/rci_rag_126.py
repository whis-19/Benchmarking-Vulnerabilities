from flask import Flask, request, jsonify, redirect, url_for, abort
import sqlite3
import hashlib
import hmac
import os
import time
import logging
from urllib.parse import urlparse, urljoin
import re

app = Flask(__name__)

# --- Configuration ---

# Use environment variables for sensitive information
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_default_secret_key')  # Fallback for development
# Ideally, generate a strong secret key:
# import secrets
# secrets.token_hex(16)
# and set it as an environment variable.
# Consider using a library like python-dotenv for managing environment variables in development.

DATABASE = 'url_shortener.db'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Database Initialization ---

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql', 'r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()

# Create the database if it doesn't exist (run once)
if not os.path.exists(DATABASE):
    init_db()

# --- Utility Functions ---

def is_safe_url(target):
    """
    Check if the target URL is safe to redirect to.  Prevents open redirects.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def generate_short_url(long_url):
    """
    Generates a short URL hash using HMAC.
    """
    key = app.config['SECRET_KEY'].encode('utf-8')
    message = long_url.encode('utf-8')
    hash = hmac.new(key, message, hashlib.sha256).hexdigest()[:8]  # 8 characters
    return hash

def is_valid_email(email):
    """
    Validates email format using a regular expression.  For production, consider using a dedicated library like email_validator.
    """
    # More robust email validation using regex (but still not perfect)
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None

# --- Rate Limiting ---
# Simple in-memory rate limiting (for demonstration purposes only).
# In production, use a more robust solution like Redis.
request_counts = {}
RATE_LIMIT = 5  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

def rate_limit_exceeded(ip_address):
    """
    Checks if the rate limit has been exceeded for a given IP address.
    """
    now = time.time()
    if ip_address in request_counts:
        requests = request_counts[ip_address]
        requests = [req_time for req_time in requests if now - req_time < RATE_LIMIT_WINDOW]
        if len(requests) >= RATE_LIMIT:
            return True
        requests.append(now)
        request_counts[ip_address] = requests
    else:
        request_counts[ip_address] = [now]
    return False

# --- Routes ---

@app.route('/', methods=['POST', 'GET'])
def shorten_url():
    """
    Handles URL shortening and displays the form.
    """
    if request.method == 'POST':
        long_url = request.form.get('long_url')
        email = request.form.get('email')

        # Input Validation
        if not long_url:
            return jsonify({'error': 'Long URL is required'}), 400
        if not is_valid_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Check if the URL is potentially malicious (basic check)
        if "javascript:" in long_url.lower():
            return jsonify({'error': 'Invalid URL'}), 400

        # Rate Limiting
        ip_address = request.remote_addr
        if rate_limit_exceeded(ip_address):
            return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

        try:
            short_url = generate_short_url(long_url)

            conn = get_db_connection()
            cursor = conn.cursor()

            # SQL Injection Prevention: Use parameterized queries
            cursor.execute("INSERT INTO urls (long_url, short_url, email) VALUES (?, ?, ?)",
                           (long_url, short_url, email))
            conn.commit()
            conn.close()

            shortened_url = url_for('redirect_to_url', short_url=short_url, _external=True)
            # Avoid directly reflecting user input in the response, even if validated.
            # Instead, provide a structured response.
            return jsonify({'shortened_url': shortened_url, 'original_url': long_url, 'email': email}), 201

        except sqlite3.Error as e:
            logger.error(f"Database error: {e}") # Use proper logging
            return jsonify({'error': 'Internal server error'}), 500

    # GET request: Display the form (basic HTML - consider using a template engine)
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>URL Shortener</title></head>
    <body>
        <h1>URL Shortener</h1>
        <form method="post">
            <label for="long_url">Long URL:</label><br>
            <input type="url" id="long_url" name="long_url"><br><br>
            <label for="email">Email:</label><br>
            <input type="email" id="email" name="email"><br><br>
            <input type="submit" value="Shorten">
        </form>
    </body>
    </html>
    '''

@app.route('/<short_url>')
def redirect_to_url(short_url):
    """
    Redirects to the original URL based on the short URL.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # SQL Injection Prevention: Use parameterized queries
        cursor.execute("SELECT long_url FROM urls WHERE short_url = ?", (short_url,))
        result = cursor.fetchone()
        conn.close()

        if result:
            long_url = result['long_url']
            # Open Redirect Prevention: Ensure the redirect is safe
            if is_safe_url(long_url):
                return redirect(long_url, code=302)
            else:
                logger.warning(f"Attempted unsafe redirect to: {long_url}")
                abort(400) # Or redirect to a safe page with a warning.
        else:
            abort(404)  # Not Found

    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        abort(500)  # Internal Server Error

# --- Error Handling ---

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad Request'}), 400

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not Found'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'error': 'Internal Server Error'}), 500

# --- Security Headers ---

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" # Adjust as needed
    return response

# --- CSRF Protection (Example - requires Flask-WTF) ---
# To enable CSRF protection, you would typically:
# 1. Install Flask-WTF: `pip install Flask-WTF`
# 2. Configure the SECRET_KEY (as shown above)
# 3. Use Flask-WTF forms in your templates.
# 4. Protect your routes with the csrf.protect() decorator (if needed).
# Example (Conceptual):
# from flask_wtf.csrf import CSRFProtect
# csrf = CSRFProtect(app)
# @app.route('/some_protected_route', methods=['POST'])
# @csrf.protect
# def some_protected_route():
#     # ... your code ...
#     pass


# --- Running the App ---

if __name__ == '__main__':
    # NEVER use debug=True in production!
    app.run(debug=True, host='0.0.0.0', port=5000)

