import os
from flask import Flask, session, render_template, redirect, url_for, request, flash, escape
from functools import wraps
import secrets
import json  # For reading config
from cryptography.fernet import Fernet  # For encryption
from datetime import timedelta
import logging
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt  # For password hashing
# from argon2 import PasswordHasher # Alternative to bcrypt

app = Flask(__name__)

# -------------------- Configuration Loading and Security Setup --------------------

# Load configuration from a separate file (e.g., config.json)
try:
    with open("config.json", "r") as f:
        config = json.load(f)
        app.config['SECRET_KEY'] = config.get('secret_key')  # Crucial for session security
        if not app.config['SECRET_KEY']:
            raise ValueError("Secret key not found in config.json")

        # Database credentials (example)
        db_host = config.get('db_host')
        db_user = config.get('db_user')
        db_password = config.get('db_password')
        db_name = config.get('db_name')

        # User credentials (hashed passwords) - REMOVE FROM CONFIG.JSON
        # users = config.get('users', {})  # Dictionary of username: hashed_password

        # Encryption key
        encryption_key = config.get('encryption_key')
        if not encryption_key:
            raise ValueError("Encryption key not found in config.json")
        app.encryption_key = encryption_key.encode()  # Store as bytes
        app.fernet = Fernet(app.encryption_key)

        # Session configuration
        app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
        app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

        # Example of reading from environment variable
        # app.config['ENCRYPTION_KEY'] = os.environ.get('ENCRYPTION_KEY')
        # if not app.config['ENCRYPTION_KEY']:
        #     raise ValueError("Encryption key not found in environment variable ENCRYPTION_KEY")
        # app.encryption_key = app.config['ENCRYPTION_KEY'].encode()

except FileNotFoundError:
    print("Error: config.json not found.  Create a config.json file with 'secret_key', 'users', and 'encryption_key'.")
    exit()
except json.JSONDecodeError:
    print("Error: Invalid JSON in config.json.")
    exit()
except ValueError as e:
    print(f"Error: {e}")
    exit()

# -------------------- Logging Setup --------------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# -------------------- CSRF Protection --------------------
csrf = CSRFProtect(app)

# -------------------- Rate Limiting --------------------
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per minute"]  # Adjust as needed
)

# -------------------- Encryption/Decryption Functions --------------------

def encrypt_data(data):
    """Encrypts sensitive data using Fernet."""
    if data:
        data_bytes = str(data).encode()
        encrypted_data = app.fernet.encrypt(data_bytes)
        return encrypted_data.decode()  # Store as string
    return None

def decrypt_data(encrypted_data):
    """Decrypts sensitive data using Fernet."""
    if encrypted_data:
        try:
            encrypted_bytes = encrypted_data.encode()
            decrypted_bytes = app.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception as e:
            logging.error(f"Decryption error: {e}")  # Log the error
            # Consider raising an exception or returning a more informative error message
            # flash("An error occurred while decrypting the data.") # Example
            return None  # Or raise the exception if appropriate
    return None


# -------------------- Authentication Decorator --------------------

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# -------------------- Hashing Function (bcrypt) --------------------

def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')


def verify_password(stored_hash, password):
    """Verifies a password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))


# -------------------- Routes --------------------

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = escape(request.form['username'])  # Sanitize username
        password = request.form['password']

        # Replace with database lookup
        # user = db.query(User).filter_by(username=username).first()
        # if user and verify_password(user.password_hash, password):
        #     session['username'] = username
        #     flash('Login successful!')
        #     logging.info(f"User {username} logged in successfully.")
        #     return redirect(url_for('info'))
        # else:
        #     flash('Invalid username or password.')
        #     logging.warning(f"Failed login attempt for user {username}.")
        #     return render_template('login.html')

        # Mock database interaction for testing
        # Replace with actual database lookup
        if username == "testuser" and verify_password("$2b$12$EXAMPLE_BCRYPT_HASH", password):
            session['username'] = username
            flash('Login successful!')
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('info'))
        else:
            flash('Invalid username or password.')
            logging.warning(f"Failed login attempt for user {username}.")
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)
    flash('You have been logged out.')
    logging.info(f"User logged out.")
    return redirect(url_for('login'))


@app.route('/info')
@login_required
def info():
    """Displays user information (username, email, last 4 SSN)."""
    # Simulate retrieving encrypted data from a database
    encrypted_email = encrypt_data("user@example.com")
    encrypted_ssn = encrypt_data("1234")

    # Store encrypted data in the session
    session['encrypted_email'] = encrypted_email
    session['encrypted_ssn'] = encrypted_ssn

    # Decrypt data only when needed for display
    email = escape(decrypt_data(session.get('encrypted_email'))) # Sanitize email
    ssn_last_4 = escape(decrypt_data(session.get('encrypted_ssn'))) # Sanitize SSN

    return render_template('info.html', username=session['username'], email=email, ssn_last_4=ssn_last_4)


@app.route('/')
def index():
    """Redirects to login page."""
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc")  # Use adhoc for development HTTPS

