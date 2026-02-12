from flask import Flask, session, request, jsonify
import os
import secrets
from functools import wraps
import bcrypt  # For password hashing
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman  # For security headers
import logging  # For logging
import re  # For input validation
from flask_session import Session  # For persistent sessions
import redis  # For Redis session store
from datetime import timedelta  # For session lifetime
from wtforms import Form, StringField, PasswordField, validators  # For input validation
from wtforms.validators import ValidationError
import bleach  # For output sanitization

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely generate a secret key for the session
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Configure session management (important for security)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_PERMANENT'] = True  # Use False for session-only cookies
app.config['SESSION_USE_SIGNER'] = True  # Add extra layer of security
app.config['SESSION_KEY_PREFIX'] = 'my_app_session:'  # Add a prefix to avoid collisions
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)  # Configure Redis connection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout
Session(app)

# In a real application, you would use a database and ORM (e.g., SQLAlchemy)
# to store user data securely.  NEVER store credentials in code.
# Replace this with a database interaction.
# For demonstration purposes, we'll keep a placeholder, but it's CRITICAL
# to replace this with a secure database.
USER_DATA = {}  # This MUST be replaced with a database

# Password complexity validation function
def password_complexity(form, field):
    password = field.data
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")
    if not re.search(r"[a-z]", password):
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not re.search(r"[0-9]", password):
        raise ValidationError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        raise ValidationError("Password must contain at least one special character.")


# WTForms for registration
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Email()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match'),
        password_complexity
    ])
    confirm = PasswordField('Repeat Password')

    def validate_username(self, username):
        # Simulate database check (replace with actual database query)
        if username.data in USER_DATA:
            raise ValidationError('Username already exists.')

    def validate_email(self, email):
        # Simulate database check (replace with actual database query)
        for user in USER_DATA.values():
            if user['email'] == email.data:
                raise ValidationError('Email address already registered.')


# WTForms for login
class LoginForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])


# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="redis://localhost:6379"  # Use Redis for persistent storage
)

# Security headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': '\'self\' https://cdnjs.cloudflare.com',  # Example: Allow scripts from CDN
        'style-src': '\'self\' https://cdnjs.cloudflare.com',  # Example: Allow styles from CDN
        'img-src': '\'self\' data:',
        'font-src': '\'self\'',
        'object-src': '\'none\'',
    },
    force_https=True,  # Enforce HTTPS
    session_cookie_secure=True,  # Ensure session cookies are secure
    session_cookie_http_only=True,  # Prevent JavaScript access to session cookies
    frame_options='DENY',  # Prevent clickjacking
    x_content_type_options='nosniff',  # Prevent MIME sniffing
    referrer_policy='same-origin',  # Control referrer information
    hsts_max_age=timedelta(days=365),  # Enable HSTS for one year
    hsts_include_subdomains=True,
    hsts_preload=True
)


# Authentication decorator (example)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            logging.warning(f"Unauthorized access attempt to {request.path} from {request.remote_addr}")
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['POST'])
def register():
    form = RegistrationForm(request.form)
    if form.validate():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store user data (replace with database interaction)
        USER_DATA[username] = {
            "username": username,
            "email": email,
            "password_hash": password_hash
        }

        logging.info(f"New user registered: {username} from {request.remote_addr}")
        return jsonify({"message": "Registration successful"}), 201
    else:
        logging.warning(f"Registration failed from {request.remote_addr}: {form.errors}")
        return jsonify({"error": form.errors}), 400


@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    form = LoginForm(request.form)
    if form.validate():
        username = form.username.data
        password = form.password.data

        # In a real application, you would authenticate against a database
        if username in USER_DATA:
            user_data = USER_DATA[username]
            if bcrypt.checkpw(password.encode('utf-8'), user_data['password_hash']):
                session['username'] = username
                session.regenerate()  # Regenerate session ID after login
                logging.info(f"User {username} logged in from {request.remote_addr}")
                return jsonify({"message": "Login successful"})
            else:
                logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}")
                return jsonify({"error": "Invalid credentials"}), 401
        else:
            logging.warning(f"Login attempt for non-existent user {username} from {request.remote_addr}")
            return jsonify({"error": "Invalid credentials"}), 401
    else:
        logging.warning(f"Login failed from {request.remote_addr}: {form.errors}")
        return jsonify({"error": form.errors}), 400


@app.route('/logout')
def logout():
    username = session.pop('username', None)
    if username:
        logging.info(f"User {username} logged out from {request.remote_addr}")
    return jsonify({"message": "Logged out"})


@app.route('/info', methods=['GET'])
@login_required  # Protect the route
def info():
    """
    Returns user information.  Sanitizes output to prevent XSS.
    """
    username = session.get('username')

    # Retrieve user data (replace with database lookup)
    user_data = USER_DATA.get(username)

    if user_data:
        # Sanitize output to prevent XSS
        safe_username = bleach.clean(user_data["username"])
        safe_email = bleach.clean(user_data["email"])

        return jsonify({
            "username": safe_username,
            "email": safe_email,
            # **DO NOT INCLUDE SSN OR PASSWORD HASH IN THE RESPONSE!**
        })
    else:
        logging.warning(f"User {username} not found while accessing /info from {request.remote_addr}")
        return jsonify({"error": "User not found"}), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded for {request.remote_addr}")
    return jsonify({"error": "Rate limit exceeded"}), 429


@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    # **WARNING:**  Do not use `debug=True` in production.  It can expose sensitive information.
    # Use a production-ready WSGI server like Gunicorn or uWSGI.
    # In production, set debug=False and use a proper WSGI server.
    app.run(debug=True, host='0.0.0.0', port=5000)

