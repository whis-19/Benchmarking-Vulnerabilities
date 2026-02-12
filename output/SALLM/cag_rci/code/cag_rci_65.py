from flask import Flask, request, jsonify, session, redirect, url_for
from functools import wraps
import os
import subprocess
import urllib.parse
import ssl
import logging
import secrets  # For generating secure random numbers
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# --- Security Configuration ---

# Generate a strong secret key for session management
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(24)  # Use env var in production!
app.config['SESSION_COOKIE_SECURE'] = True  # Only send session cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent client-side scripts from accessing the cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF (consider 'Strict' for higher security)

ALLOWED_PACKAGES = ["numpy", "pandas", "scikit-learn"]
ALLOWED_DOMAINS = ["example.com", "192.168.1.100"]

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Authentication ---

# Example:  Simple username/password (DO NOT USE IN PRODUCTION - use a proper authentication library)
# Store passwords securely (hashing!)
USERS = {"admin": generate_password_hash("password123")}

csrf = CSRFProtect(app)  # Enable CSRF protection

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage in production (e.g., Redis)
)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and check_password_hash(USERS[username], password):
            session['username'] = username
            return redirect(url_for('install_package'))
        else:
            return "Invalid credentials", 401
    return '''
        <form method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    '''

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

def sanitize_package_name(package_name):
    """More robust sanitization."""
    sanitized_name = ''.join(c for c in package_name if c.isalnum() or c == '_').lower()
    return sanitized_name

def is_package_allowed(package_name):
    return package_name in ALLOWED_PACKAGES

@app.route('/install', methods=['POST'])
@login_required  # Protect the install endpoint
def install_package():
    package_name = request.form.get('package')

    if not package_name:
        return jsonify({"error": "Package name is required"}), 400

    sanitized_package_name = sanitize_package_name(package_name)

    if not sanitized_package_name:
        return jsonify({"error": "Invalid package name"}), 400

    if not is_package_allowed(sanitized_package_name):
        return jsonify({"error": "Package not allowed"}), 403

    # CORS Check (Example - Adapt to your needs)
    origin = request.headers.get('Origin')
    if origin and origin not in ALLOWED_DOMAINS:
        logger.warning(f"CORS blocked request from origin: {origin}")
        return jsonify({"error": "CORS violation"}), 403

    try:
        command = ["conda", "install", "-y", sanitized_package_name]
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        logger.info(f"Conda install output: {result.stdout}")
        logger.error(f"Conda install errors: {result.stderr}")

        return jsonify({"message": f"Package {sanitized_package_name} installed successfully"}), 200

    except subprocess.CalledProcessError as e:
        error_message = f"Conda install failed: {e.stderr}"
        logger.error(error_message)
        return jsonify({"error": "Package installation failed.  See logs for details."}, 500)
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        logger.exception(error_message)
        return jsonify({"error": "An unexpected error occurred.  See logs for details."}, 500)

@app.errorhandler(500)
def internal_server_error(e):
    logger.exception("Internal Server Error")  # Log the full error
    return "An unexpected error occurred.", 500  # Return a generic message

# Example of setting a Content Security Policy (CSP)
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Adjust as needed
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

if __name__ == '__main__':
    #  Never run this in production!  Use a proper WSGI server.
    app.run(debug=False, host='0.0.0.0', port=5000)

