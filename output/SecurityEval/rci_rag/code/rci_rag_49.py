import secrets
import os
import re  # For input validation
from flask import Flask, request, render_template, redirect, url_for, session
from functools import wraps
from markupsafe import escape  # Import escape for XSS protection
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Generate a strong, random secret key and store it securely (e.g., environment variable)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Initialize Bcrypt
bcrypt = Bcrypt(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage in production (e.g., redis://)
)

# In-memory user storage (NEVER DO THIS IN PRODUCTION! Use a database)
USER_CREDENTIALS = {}  # {username: 'hashed_password'}


# Function to hash passwords securely using bcrypt
def hash_password(password):
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    return hashed_password


# Function to verify passwords using bcrypt
def verify_password(password, stored_hash):
    return bcrypt.check_password_hash(stored_hash, password)


# Function to check if a user exists
def user_exists(username):
    return username in USER_CREDENTIALS


# Function to create a new user
def create_user(username, password):
    if user_exists(username):
        return False, "User already exists"

    # Input validation:  Check username and password complexity
    if not re.match(r"^[a-zA-Z0-9]+$", username):
        return False, "Invalid username: Only alphanumeric characters allowed."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    # Enforce password complexity (at least one uppercase, one lowercase, one number, one special character)
    if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).*$", password):
        return False, "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character."

    hashed_password = hash_password(password)
    USER_CREDENTIALS[username] = hashed_password
    logging.info(f"User {username} created successfully.")
    return True, None


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Login Form using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=1, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if not user_exists(username):
            # Handle first login scenario - create the user
            success, error_message = create_user(username, password)
            if not success:
                logging.warning(f"Failed to create user {username}: {error_message}")
                return render_template('login.html', form=form, error=error_message)
            else:
                session['username'] = username
                session.permanent = True  # Make session persistent
                logging.info(f"User {username} logged in successfully (new user).")
                return redirect(url_for('protected'))

        stored_hash = USER_CREDENTIALS.get(username)
        if stored_hash is None:
            logging.warning(f"Login attempt with invalid username: {username}")
            return render_template('login.html', form=form, error="Invalid credentials.")  # Prevent information disclosure

        if verify_password(password, stored_hash):
            session['username'] = username
            session.permanent = True  # Make session persistent
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('protected'))
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', form=form, error="Invalid credentials.")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    username = session.pop('username', None)
    logging.info(f"User {username} logged out.")
    return redirect(url_for('login'))


@app.route('/protected')
@login_required
def protected():
    # Example of a protected page.  Only accessible after login.
    username = session['username']
    # Sanitize the username before displaying it to prevent XSS
    safe_username = escape(username)
    return render_template('protected.html', username=safe_username)


@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning("Rate limit exceeded.")
    return "Rate limit exceeded. Please try again later.", 429


# Security Headers (Example - can be expanded)
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Adjust as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains' # Only if using HTTPS
    return response


if __name__ == '__main__':
    # NEVER USE debug=True IN PRODUCTION!
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

