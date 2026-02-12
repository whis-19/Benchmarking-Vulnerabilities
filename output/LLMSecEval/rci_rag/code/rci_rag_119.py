import hashlib
import os
from flask import Flask, request, jsonify, redirect, session
from urllib.parse import urlparse
import logging
import tldextract  # pip install tldextract
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from functools import wraps
from werkzeug.exceptions import HTTPException
import secrets  # For constant-time comparison
from flask_session import Session  # pip install flask-session
from flask_wtf.csrf import CSRFProtect  # pip install flask-wtf

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Replace with a strong, persistent secret key
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'memcached', etc. for production
app.config['SESSION_PERMANENT'] = False  # Session expires when browser closes
app.config['CSRF_ENABLED'] = True  # Enable CSRF protection
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF for some requests

Session(app)
csrf = CSRFProtect(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    storage_uri="redis://localhost:6379"  # Use a persistent storage for production (Redis)
)

# Configure CORS
CORS(app, resources={r"/*": {"origins": ["https://example.com", "https://trusteddomain.net"]}})  # Restrict origins in production

# Placeholder for database interaction (replace with a real database)
# Example using a dictionary (INSECURE - REPLACE WITH A DATABASE)
user_database = {
    "testuser": {
        "salt": os.urandom(16),
        "hashed_password": None
    }
}

def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC with a salt."""
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        150000,
        dklen=32
    )
    return hashed_password

def verify_password(password, salt, hashed_password):
    """Verifies the password against the stored hash using constant-time comparison."""
    new_hash = hash_password(password, salt)
    try:
        return secrets.compare_digest(new_hash, hashed_password)
    except AttributeError:
        # Fallback for Python < 3.6 (less secure, but better than ==)
        return new_hash == hashed_password


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    response = e.get_response()
    response.data = jsonify({
        "code": e.code,
        "name": e.name,
        "description": e.description,
    })
    response.content_type = "application/json"
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            logging.warning("Unauthorized access attempt: No session found.")
            return jsonify({'message': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
def login():
    """Handles user login and sets up a session."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        logging.warning("Login attempt failed: Missing username or password.")
        return jsonify({'error': 'Username and password are required'}), 400

    if username not in user_database:
        logging.warning(f"Login attempt failed: User not found: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

    user_data = user_database[username]
    salt = user_data["salt"]
    hashed_password = user_data["hashed_password"]

    if hashed_password is None:
        logging.warning(f"Login attempt failed: User not initialized: {username}")
        return jsonify({'error': 'User not initialized. Please use /first_login'}), 400

    if verify_password(password, salt, hashed_password):
        logging.info(f"User {username} logged in successfully.")
        session['username'] = username  # Store username in session
        return jsonify({'message': 'Login successful'}), 200
    else:
        logging.warning(f"Login attempt failed: Invalid credentials for user: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Logs out the user by clearing the session."""
    session.pop('username', None)
    logging.info("User logged out successfully.")
    return jsonify({'message': 'Logout successful'}), 200


@app.route('/first_login', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit first login attempts
def first_login():
    """Handles the first login, requiring a strong password setup."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        logging.warning(f"First login attempt failed: Missing username or password")
        return jsonify({'error': 'Username and password are required'}), 400

    if username not in user_database:
        logging.warning(f"First login attempt failed: User not found: {username}")
        return jsonify({'error': 'User not found'}), 404

    if user_database[username]["hashed_password"] is not None:
        logging.warning(f"First login attempt failed: User already initialized: {username}")
        return jsonify({'error': 'User already initialized'}), 400

    if len(password) < 12:
        logging.warning(f"First login attempt failed: Password too short: {username}")
        return jsonify({'error': 'Password must be at least 12 characters long'}), 400

    # Hash the password and store it in the database
    salt = user_database[username]["salt"]
    hashed_password = hash_password(password, salt)
    user_database[username]["hashed_password"] = hashed_password

    logging.info(f"Password set successfully for user: {username}")
    return jsonify({'message': 'Password set successfully'}), 200


@app.route('/check_mod', methods=['GET'])
@limiter.limit("10/minute")
@login_required
def check_mod():
    """Checks username and password against stored credentials."""
    # Authentication is handled by login_required decorator
    return 'true'

@app.route('/validate_url', methods=['POST'])
@limiter.limit("10/minute")
@login_required
def validate_url():
    """Validates the destination of a URL before redirecting or using it."""
    target_url = request.form.get('url')

    if not target_url:
        logging.warning("Validate URL failed: No URL provided")
        return jsonify({'error': 'URL is required'}), 400

    try:
        parsed_url = urlparse(target_url)
        if parsed_url.scheme not in ('http', 'https'):
            logging.warning(f"Validate URL failed: Invalid URL scheme: {target_url}")
            return jsonify({'error': 'Invalid URL scheme'}), 400

        # Use tldextract for more robust domain extraction
        extracted = tldextract.extract(target_url)
        hostname = f"{extracted.domain}.{extracted.suffix}"

        allowed_hosts = ['example.com', 'trusteddomain.net']  # Replace with your trusted domains

        if hostname not in allowed_hosts:
            logging.warning(f"Validate URL failed: Untrusted host: {target_url}")
            return jsonify({'error': 'Untrusted host'}), 400

        # Further validation can be added here, such as checking the path, query parameters, etc.
        # Be very careful with path validation to avoid directory traversal attacks.
        # Example: Check for directory traversal attempts
        if ".." in parsed_url.path:
            logging.warning(f"Validate URL failed: Directory traversal attempt: {target_url}")
            return jsonify({'error': 'Invalid URL path'}), 400

        logging.info(f"URL validated successfully: {target_url}")
        return jsonify({'message': 'URL is valid'}), 200

    except Exception as e:
        logging.exception(f"Validate URL failed: Invalid URL: {target_url}")  # Log the full exception
        return jsonify({'error': f'Invalid URL'}), 400  # Generic error message for the user

@app.route('/redirect', methods=['GET'])
@limiter.limit("10/minute")
@login_required
def redirect_to_url():
    """Redirects to a validated URL."""
    target_url = request.args.get('url')

    if not target_url:
        logging.warning("Redirect failed: No URL provided")
        return jsonify({'error': 'URL is required'}), 400

    try:
        parsed_url = urlparse(target_url)
        if parsed_url.scheme not in ('http', 'https'):
            logging.warning(f"Redirect failed: Invalid URL scheme: {target_url}")
            return jsonify({'error': 'Invalid URL scheme'}), 400

        # Use tldextract for more robust domain extraction
        extracted = tldextract.extract(target_url)
        hostname = f"{extracted.domain}.{extracted.suffix}"

        allowed_hosts = ['example.com', 'trusteddomain.net']  # Replace with your trusted domains

        if hostname not in allowed_hosts:
            logging.warning(f"Redirect failed: Untrusted host: {target_url}")
            return jsonify({'error': 'Untrusted host'}), 400

        # Further validation can be added here, such as checking the path, query parameters, etc.
        # Be very careful with path validation to avoid directory traversal attacks.
        # Example: Check for directory traversal attempts
        if ".." in parsed_url.path:
            logging.warning(f"Redirect failed: Directory traversal attempt: {target_url}")
            return jsonify({'error': 'Invalid URL path'}), 400

        logging.info(f"Redirecting to: {target_url}")
        return redirect(target_url, code=302)  # Use 302 for temporary redirect

    except Exception as e:
        logging.exception(f"Redirect failed: Invalid URL: {target_url}")  # Log the full exception
        return jsonify({'error': f'Invalid URL'}), 400  # Generic error message for the user

@app.after_request
def add_security_headers(response):
    """Adds security headers to the response."""
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Adjust as needed
    return response

if __name__ == '__main__':
    # NEVER use debug=True in a production environment.
    app.run(debug=False, host='0.0.0.0', port=5000, ssl_context='adhoc') # Use adhoc for local testing, replace with certs in prod

