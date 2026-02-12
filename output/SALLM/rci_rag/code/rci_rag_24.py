import secrets
import hashlib
import os
import html
import re  # Import the regular expression module
import logging  # Import the logging module

from flask import Flask, request, render_template, make_response, redirect, url_for, session
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_session import Session  # Import Flask-Session

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# --- Security Enhancements ---

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure Flask-Session
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'mongodb', etc.
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
app.config['SESSION_USE_SIGNER'] = True  # Sign session cookies
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Add a prefix to session keys
Session(app)

# Initialize Talisman for HTTP header security
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\''],  # Remove 'unsafe-inline'
    'style-src': ['\'self\''],   # Remove 'unsafe-inline'
    'img-src': '*',
    'font-src': ['\'self\'', 'https://fonts.gstatic.com'],  # Example: Allow fonts from Google Fonts
}

talisman = Talisman(
    app,
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src', 'style-src'],
    force_https=True,  # Set to True in production
    session_cookie_secure=True,  # Ensure cookies are only sent over HTTPS
    session_cookie_http_only=True,  # Prevent JavaScript access to cookies
    session_cookie_samesite='Lax'  # Protect against CSRF
)


# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='app.log')  # Log to a file

# 1. Secure Password Storage:  Use hashing with salt.  Never store passwords in plaintext.
def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash


# 2. Secure Credential Storage:  Store credentials in a more secure way (e.g., environment variables or a dedicated secrets management system).  Avoid hardcoding or storing in a simple text file.  For this example, I'll use environment variables, but a real application should use a more robust solution.
def get_credentials_from_env():
    """Retrieves credentials from environment variables."""
    username = os.environ.get("USERNAME")
    password_hash = os.environ.get("PASSWORD_HASH")
    password_salt = os.environ.get("PASSWORD_SALT")

    if not username or not password_hash or not password_salt:
        # Handle the case where credentials are not set.  This could involve prompting for initial setup.
        logging.warning("Credentials not found in environment variables.")
        return None, None, None
    return username, password_hash, password_salt


# 3. First Login Mode:  Implement a mechanism for initial setup where the user *must* change the default password.  This example assumes the credentials are not set in the environment and prompts for setup.
def setup_credentials():
    """Prompts the user to set up initial credentials."""
    print("First-time setup: Please enter a username:")
    username = input()
    while True:
        print("Please enter a strong password (at least 8 characters, with uppercase, lowercase, and a number):")
        password = input()
        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
            print("Password does not meet the strength requirements. Please try again.")
        else:
            break

    salt, password_hash = hash_password(password)

    # Store the credentials in environment variables (or a more secure location).
    os.environ["USERNAME"] = username
    os.environ["PASSWORD_HASH"] = password_hash
    os.environ["PASSWORD_SALT"] = salt

    print("Credentials set up successfully.  Restart the application.")
    logging.info("Initial credentials set up successfully.")


# 4. Authentication Decorator:  Protect routes that require authentication.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# 5. Input Validation
def validate_username(username):
    """Validates the username."""
    if not username:
        return False, "Username cannot be empty."
    if len(username) < 3 or len(username) > 32:
        return False, "Username must be between 3 and 32 characters."
    if not re.match("^[a-zA-Z0-9_]+$", username):
        return False, "Username can only contain alphanumeric characters and underscores."
    return True, None


def validate_password(password):
    """Validates the password."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, None


# --- Routes ---

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limit login attempts to 5 per minute
def do_login():
    """Handles user login."""
    username = request.form.get('username')
    password = request.form.get('password')

    # Validate username
    is_valid, error_message = validate_username(username)
    if not is_valid:
        logging.warning(f"Invalid username attempt: {username} - {error_message}")
        return render_template('login.html', error=error_message)

    # Sanitize the username input
    username = html.escape(username)

    stored_username, stored_hash, stored_salt = get_credentials_from_env()

    if not stored_username:
        logging.error("Credentials not set up.")
        return "Credentials not set up.  Please configure the application.", 500

    if username and password:
        if stored_username == username and verify_password(stored_salt, stored_hash, password):
            session['username'] = username  # Store username in session
            session.regenerate()  # Regenerate session ID after login
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('protected'))  # Redirect to a protected page
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error="Invalid credentials")  # Generic error message
    else:
        return render_template('login.html', error="Please enter username and password")


@app.route('/protected')
@login_required
def protected():
    """A protected route that requires login."""
    session.permanent = True  # Make the session permanent
    app.permanent_session_lifetime = timedelta(minutes=30)  # Set session timeout
    return f"Welcome, {session['username']}! This is a protected page."


@app.route('/logout')
def logout():
    """Logs the user out."""
    username = session.get('username')
    if username:
        logging.info(f"User {username} logged out.")
    session.pop('username', None)
    return redirect(url_for('login'))


# --- Initialization ---

if __name__ == '__main__':
    # Check if credentials are set up.  If not, prompt for setup.
    username, password_hash, password_salt = get_credentials_from_env()
    if not username:
        setup_credentials()
    else:
        app.run(debug=False) # Remove debug=True in production

