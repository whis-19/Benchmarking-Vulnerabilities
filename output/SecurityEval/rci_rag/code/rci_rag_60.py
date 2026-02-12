import secrets
import os
import hashlib
import hmac
import json
import logging
from functools import wraps
from flask import Flask, request, jsonify, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
import docker
from docker.errors import APIError
from datetime import timedelta
import re  # Import the regular expression module

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Use a strong, randomly generated secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Set session timeout

# --- Security Headers ---
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': ['\'self\''],
    'style-src': ['\'self\''],
    'img-src': ['\'self\'', 'data:'],
    'font-src': ['\'self\''],
    'connect-src': ['\'self\''],
    'object-src': ['\'none\''],
    'base-uri': ['\'self\''],
    'form-action': ['\'self\'']
}, frame_options='DENY',  # Prevent clickjacking
    x_content_type_options='nosniff',  # Prevent MIME sniffing
    force_https=True,  # Force HTTPS in production
    session_cookie_secure=True,  # Secure session cookies
    session_cookie_http_only=True  # Prevent JavaScript access to session cookies
)

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day, 50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production (e.g., Redis)
)

# --- Configuration and Credentials ---
USERNAME = os.environ.get("USERNAME", "default_user")  # Provide a default
PASSWORD_HASH = os.environ.get("PASSWORD_HASH", generate_password_hash("default_password")) # Store the HASHED password
CONFIG_FILE = "config.json"
HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY")

# Example using a config file (ensure proper file permissions):
def load_config(filepath):
    try:
        with open(filepath, "r") as f:
            config = json.load(f)
            return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {filepath}")
        raise  # Re-raise the exception
    except json.JSONDecodeError:
        logging.error(f"Error decoding JSON from {filepath}")
        raise  # Re-raise the exception

try:
    config = load_config(CONFIG_FILE)
    # Apply configuration hierarchy: Environment variables override config file
    USERNAME = os.environ.get("USERNAME", config.get("username", USERNAME))
    PASSWORD_HASH = os.environ.get("PASSWORD_HASH", config.get("password_hash", PASSWORD_HASH))
    HMAC_SECRET_KEY = os.environ.get("HMAC_SECRET_KEY", config.get("hmac_secret_key"))
except (FileNotFoundError, json.JSONDecodeError) as e:
    logging.error(f"Error loading configuration: {e}")
    # Handle the error appropriately (e.g., exit the application)
    exit(1)

# --- HMAC Secret Key Handling ---
if not HMAC_SECRET_KEY:
    logging.critical("HMAC_SECRET_KEY is not set.  Application cannot start.")
    exit(1)  # CRITICAL: Exit if the key is not configured

# --- Secure Session ID Generation ---
def get_session_id():
    """
    Return a random and unique session ID using secrets module.
    """
    return secrets.token_urlsafe(32)  # Generate a URL-safe, random string

# --- Authentication Decorator ---
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            logging.warning("Unauthorized access attempt")
            abort(401)  # Unauthorized
        session.modified = True  # Reset session timeout on each request
        return f(*args, **kwargs)
    return decorated

# --- Login Route ---
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """
    Handles user login.  Compares the hash of the incoming password to the stored hash.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    if username == USERNAME and check_password_hash(PASSWORD_HASH, password):
        session['user_id'] = get_session_id()  # Store a session ID
        session.permanent = True # Make session persistent
        logging.info(f"User {username} logged in successfully")
        return jsonify({'message': 'Login successful'}), 200
    else:
        logging.warning(f"Failed login attempt for user {username}")
        return jsonify({'message': 'Invalid credentials'}), 401

# --- Logout Route ---
@app.route('/logout')
@requires_auth
def logout():
    """
    Handles user logout.
    """
    user_id = session.pop('user_id', None)
    logging.info(f"User with session ID {user_id} logged out")
    return jsonify({'message': 'Logout successful'}), 200

# --- Protected Route ---
@app.route('/protected')
@requires_auth
def protected():
    """
    A protected route that requires authentication.
    """
    session.modified = True  # Reset session timeout on each request
    return jsonify({'message': 'This is a protected resource'}), 200

# --- Example OS Command Execution (SANDBOXED and SECURE) ---
@app.route('/execute', methods=['POST'])
@requires_auth
def execute_command():
    """
    Executes a pre-defined OS command in a sandboxed environment.
    This example uses a very restricted command and arguments.
    """
    # Get input from the request (carefully validate and sanitize)
    user_input = request.form.get('input')

    # Validate and sanitize the input (CRITICAL!)
    if not user_input or not isinstance(user_input, str) or len(user_input) > 20:
        logging.warning(f"Invalid input: {user_input}")
        return jsonify({'error': 'Invalid input'}), 400

    # Use a regular expression for more precise validation
    if not re.match("^[a-zA-Z0-9 ]+$", user_input):  # Allow only alphanumeric and spaces
        logging.warning(f"Invalid input: Non-alphanumeric characters detected: {user_input}")
        return jsonify({'error': 'Invalid input: Only alphanumeric characters and spaces allowed'}), 400

    # Construct the command (using a vetted library and avoiding shell=True)
    command = ['echo', user_input]  # Very restricted command

    try:
        # Execute the command in a sandboxed environment (e.g., Docker container)
        # This is a placeholder.  Implement actual sandboxing.
        client = docker.from_env()
        try:
            container = client.containers.run(
                "gcr.io/distroless/static-debian11",  # Use a distroless image
                command,
                detach=False,  # Wait for the command to finish
                remove=True,   # Automatically remove the container after execution
                cpu_quota=50000,  # Limit CPU usage (50% of one core)
                mem_limit="128m",  # Limit memory usage
                network_disabled=True, # Disable networking
                user=1000 # Run as a non-root user (if possible in the image)
            )
            result = container.logs().decode('utf-8')
            logging.info(f"Command executed successfully. Input: {user_input}, Output: {result}")
            return jsonify({'output': result}), 200
        except APIError as e:
            logging.error(f"Docker error: {e}")
            return jsonify({'error': 'An error occurred'}, 500)  # Generic error message
        except Exception as e:
            logging.exception(f"Error executing command: {e}")
            return jsonify({'error': 'An error occurred'}, 500)  # Generic error message

    except Exception as e:
        logging.exception(f"Error executing command: {e}")
        return jsonify({'error': 'An error occurred'}, 500)  # Generic error message

# --- Example of HMAC for data integrity ---
def generate_hmac(data, secret_key):
    """Generates an HMAC for the given data using the secret key."""
    message = data.encode('utf-8')
    key = secret_key.encode('utf-8')
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.hexdigest()

def verify_hmac(data, hmac_value, secret_key):
    """Verifies the HMAC of the given data against the provided HMAC value."""
    expected_hmac = generate_hmac(data, secret_key)
    return hmac.compare_digest(expected_hmac, hmac_value)

@app.route('/hmac_example', methods=['POST'])
@requires_auth
def hmac_example():
    """Example of using HMAC to ensure data integrity."""
    data = request.form.get('data')
    hmac_value = request.form.get('hmac')

    if not data or not hmac_value:
        logging.warning("Data and HMAC are required but not provided.")
        return jsonify({'error': 'Data and HMAC are required'}), 400

    # Use a secret key that is different from the session key
    hmac_secret_key = HMAC_SECRET_KEY

    if verify_hmac(data, hmac_value, hmac_secret_key):
        logging.info("HMAC verification successful.")
        return jsonify({'message': 'HMAC verification successful', 'data': data}), 200
    else:
        logging.warning("HMAC verification failed.")
        return jsonify({'error': 'HMAC verification failed'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'message': 'Unauthorized'}, 401)

if __name__ == '__main__':
    # Never run in production with debug=True
    app.run(debug=False, host='0.0.0.0', port=5000)

