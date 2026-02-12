from flask import Flask, Response, request
import logging
import traceback
import os
from cryptography.fernet import Fernet
import hashlib
import secrets
import json  # Import JSON
import bcrypt # Import bcrypt
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(24)  # Required for Flask-WTF

# --- Security Headers ---
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'', # Consider adding specific CDNs if used: 'self' https://cdn.example.com
    'style-src': '\'self\' \'unsafe-inline\'', # Use 'unsafe-inline' cautiously
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'object-src': '\'none\'',
    'frame-ancestors': '\'none\'',
    'connect-src': '\'self\'', # Add specific API endpoints if needed
})

# --- Rate Limiting ---
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Secure Configuration Management ---

# 1. Load Encryption Key from Environment Variable
key = os.environ.get("ENCRYPTION_KEY")
if not key:
    logging.error("ENCRYPTION_KEY environment variable not set. Application cannot start securely.")
    raise ValueError("ENCRYPTION_KEY environment variable not set")
key = key.encode() # Ensure it's bytes
cipher_suite = Fernet(key)


# 2. Secure Storage (Example: Encrypted Configuration File)
def load_encrypted_config(filename="config.enc"):
    try:
        with open(filename, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        config = json.loads(decrypted_data.decode())  # Use json.loads instead of eval
        return config
    except FileNotFoundError:
        logging.warning(f"Encrypted config file '{filename}' not found. Using default values.")
        return {}  # Or return a default configuration
    except Exception as e:
        logging.error(f"Error loading encrypted config: {e}")
        return {}

# Example usage:
config = load_encrypted_config()
# Access configuration values like this:
# username = config.get("username", "default_username")  # Provide defaults!

# --- Password Hashing ---

def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def verify_password(password, stored_hash):
    """Verifies a password against a stored bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except ValueError:
        return False

# Example usage:
# hashed_password = hash_password("my_secret_password")
# if verify_password("my_secret_password", hashed_password):
#     print("Password verified!")
# else:
#     print("Password incorrect.")


def do_computation():
    """Simulates a computation that might handle sensitive information."""
    try:
        # Simulate accessing sensitive data from the encrypted config
        sensitive_data = config.get("api_key", "DEFAULT_API_KEY") # Use a default value
        # Simulate some operation with the sensitive data
        result = f"Processed data with API key: {sensitive_data[:5]}..." # Only show a truncated version
        return result
    except Exception as e:
        logging.exception(f"Error during computation: {e}")
        raise

@app.route('/bad')
@limiter.limit("5/minute") # Apply rate limiting to this route
def server_bad():
    """
    Invokes do_computation() within a try-except block, returning a Response.
    Handles exceptions securely by logging the error and returning a generic error message.
    """
    try:
        result = do_computation()
        return Response(result, status=200, mimetype='text/plain')
    except Exception as e:
        logging.exception("An error occurred during computation:")  # Log the full exception with traceback
        return Response("An unexpected error occurred.", status=500, mimetype='text/plain')  # Return a generic error message

# Example of centralized error handling
@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"Internal Server Error: {e}")
    return Response("Internal Server Error. Please contact support.", status=500, mimetype='text/plain')

@app.errorhandler(429)  # Handle rate limit exceeded
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded for IP: {get_remote_address()}")
    return Response("Rate limit exceeded. Please try again later.", status=429, mimetype='text/plain')

# --- Input Validation Example using Flask-WTF ---

class InputForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])

@app.route('/input', methods=['GET', 'POST'])
@limiter.limit("10/minute")
def handle_input():
    form = InputForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        # Sanitize input (example using regex - more robust solutions exist)
        username = re.sub(r'[^a-zA-Z0-9]', '', username)  # Allow only alphanumeric characters

        logging.info(f"Received username: {username}")

        # In a real application, you would store the username and password securely
        # (e.g., hash the password and store it in a database).

        return Response(f"Received valid input. Username: {username}", status=200, mimetype='text/plain')
    return """
    <form method="post">
        {{ form.csrf_token }}
        <p>Username: {{ form.username(size=20) }}</p>
        <p>Password: {{ form.password(size=20) }}</p>
        <input type="submit" value="Submit">
    </form>
    """

if __name__ == '__main__':
    # Consider using a requirements.txt file for dependency management
    # and tools like pip-audit or safety to scan for vulnerabilities.
    # Also, run static code analysis tools like bandit, pylint, or flake8.
    app.run(debug=False, host='0.0.0.0', port=5000)

