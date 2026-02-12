from flask import Flask, session, redirect, url_for, request, render_template, make_response
import os
import secrets
from functools import wraps
from cryptography.fernet import Fernet
import json
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from bleach import clean  # For sanitizing input
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email
from flask_talisman import Talisman
import logging

app = Flask(__name__)

# Securely generate a secret key for the session
app.secret_key = secrets.token_hex(24)

# Session security settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# CSRF Protection
csrf = CSRFProtect(app)

# Load configuration from a separate file
try:
    config_path = os.environ.get("CONFIG_PATH", "config.json")  # Use env var for config path
    with open(config_path, "r") as f:
        config = json.load(f)
        USERNAME = config.get("username")
        PASSWORD_HASH = config.get("password_hash")  # Store password as a bcrypt hash
        FERNET_KEY = config.get("fernet_key") # Key for encryption
        if not all([USERNAME, PASSWORD_HASH, FERNET_KEY]):
            raise ValueError("Missing configuration values in config.json")
except FileNotFoundError:
    print("Error: config.json not found.  Please create it with username, password_hash, and fernet_key.")
    exit()
except json.JSONDecodeError:
    print("Error: Invalid JSON in config.json.")
    exit()
except ValueError as e:
    print(f"Error: {e}")
    exit()


# Initialize Fernet for encryption/decryption
fernet = Fernet(FERNET_KEY.encode())

# Initialize Talisman for security headers
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': ['\'self\''],
    'style-src': ['\'self\''],
    'img-src': ['\'self\'', 'data:'],
    'font-src': ['\'self\''],
    'connect-src': ['\'self\'']
}, force_https=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to hash passwords (use a strong hashing algorithm like bcrypt or scrypt in production)
def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    """Checks if the password matches the hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# Function to encrypt sensitive data
def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()


# Function to decrypt sensitive data
def decrypt_data(data):
    """Decrypts data using Fernet."""
    decrypted_data = fernet.decrypt(data.encode()).decode()
    return decrypted_data


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Login Form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=100)])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Sanitize username (example - more thorough sanitization might be needed)
        username = clean(username)

        if username == USERNAME and check_password(password, PASSWORD_HASH):
            session['username'] = username

            # Store user data in session, encrypting sensitive information
            session['encrypted_email'] = encrypt_data("user@example.com")
            # Consider removing SSN storage entirely.  If absolutely necessary, implement tokenization, masking, and strong access controls.
            # For demonstration purposes, we'll keep it, but this is HIGHLY discouraged.
            session['encrypted_ssn'] = encrypt_data("123-45-6789")

            next_page = request.args.get('next')
            return redirect(next_page or url_for('info'))
        else:
            error = 'Invalid credentials'
    return render_template('login.html', form=form, error=error)


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('encrypted_email', None)
    session.pop('encrypted_ssn', None)
    return redirect(url_for('login'))


@app.route('/info')
@login_required
def info():
    """Returns user information (username, email, SSN) after decryption."""

    username = session['username']
    email = decrypt_data(session['encrypted_email'])
    ssn = decrypt_data(session['encrypted_ssn'])

    #  Do not log sensitive information
    #  app.logger.info(f"User {username} accessed info page.") # Avoid logging sensitive data

    # Set Cache-Control headers to prevent caching
    response = make_response(render_template('info.html', username=username, email=email, ssn=ssn))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response


@app.route('/')
def index():
    return redirect(url_for('login'))


# Example of a route that requires a POST request and CSRF protection
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    # This route is just an example and doesn't actually update anything.
    # It's here to demonstrate how to use CSRF protection with POST requests.
    if request.method == 'POST':
        # Validate the CSRF token
        if not csrf.validate(request.form.get('csrf_token')):
            logging.warning("CSRF validation failed!")
            return "CSRF validation failed!", 400  # Or redirect to an error page

        # Process the form data (e.g., update user profile)
        logging.info("Profile updated successfully (not really).")
        return "Profile updated successfully!"
    else:
        return "Method not allowed", 405


# Error handling
@app.errorhandler(500)
def internal_server_error(e):
    app.logger.error(f"Internal Server Error: {e}")
    return "An internal server error occurred. Please try again later.", 500

@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404

if __name__ == '__main__':
    # Consider using environment variables for sensitive configuration
    # For example:
    # USERNAME = os.environ.get("USERNAME")
    # PASSWORD_HASH = os.environ.get("PASSWORD_HASH")
    # FERNET_KEY = os.environ.get("FERNET_KEY")

    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

