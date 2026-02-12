from flask import Flask, render_template, request, make_response, session, redirect, url_for, abort
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, Regexp, Length, EqualTo
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import os
import logging
import secrets
import email_validator
from datetime import timedelta
from werkzeug.security import generate_password_hash, check_password_hash  # For secure password handling
import redis  # For Redis session storage

app = Flask(__name__)

# Generate a cryptographically secure secret key
app.config['SECRET_KEY'] = secrets.token_hex(24)

# Configure CSRF protection
csrf = CSRFProtect(app)

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"  # Use Redis for persistent storage in production
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Strict username validation using a regular expression allowlist
USERNAME_REGEX = r"^[a-zA-Z0-9_-]+$"  # Only allow alphanumeric characters, underscores, and hyphens

# Robust email validation regex (still not perfect, but better)
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

def is_safe_username(username):
    """
    Validates the username against a strict allowlist.
    """
    if not isinstance(username, str):
        return False
    return re.match(USERNAME_REGEX, username) is not None

class MyForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Regexp(USERNAME_REGEX, message="Invalid username. Only alphanumeric characters, underscores, and hyphens are allowed."), Length(max=50, message="Name must be less than 50 characters")])
    email = EmailField('Email', validators=[DataRequired(), Email(message="Invalid email address."), Length(max=100, message="Email must be less than 100 characters")])
    submit = SubmitField('Submit')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Regexp(USERNAME_REGEX, message="Invalid username. Only alphanumeric characters, underscores, and hyphens are allowed."), Length(min=4, max=50, message="Username must be between 4 and 50 characters")])
    email = EmailField('Email', validators=[DataRequired(), Email(message="Invalid email address."), Length(max=100, message="Email must be less than 100 characters")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message="Password must be at least 8 characters")])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Configure session management
app.config['SESSION_TYPE'] = 'redis'  # Use Redis for session storage
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)  # Example: 31 days
app.config['SESSION_REDIS'] = redis.Redis(host='localhost', port=6379, db=0)  # Configure Redis connection

# Initialize session
from flask_session import Session
Session(app)

# In-memory user database (replace with a real database in production)
users = {}

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration with secure password hashing."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Check if username or email already exists
        if username in users or any(user['email'] == email for user in users.values()):
            return "Username or email already registered.", 400

        # Hash the password securely
        hashed_password = generate_password_hash(password)

        # Store user data (replace with database storage in production)
        users[username] = {'email': email, 'password': hashed_password}

        logging.info(f"New user registered: Username={username}, Email={email}")
        return "Registration successful! Please log in."

    return render_template('register.html', form=form)

@app.route('/hello/<username>')
@limiter.limit("10 per minute")
def hello(username):
    """
    Greets the user with the given username.
    """
    if not is_safe_username(username):
        logging.warning(f"Invalid username attempt: {username}")
        abort(400, "Invalid username.  Only alphanumeric characters, underscores, and hyphens are allowed.")  # Return a 400 Bad Request error

    # Create a response object
    response = make_response(render_template('hello.html', username=username))

    # Set security headers (moved to after_request for consistency)

    return response

@app.after_request
def add_security_headers(response):
    """
    Adds security headers to every response.
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload' #Enforce HTTPS
    response.headers['Content-Type'] = 'text/html; charset=utf-8' # Explicitly set content type
    return response

@app.route('/form', methods=['POST', 'GET'])
@limiter.limit("5 per minute")
def form_example():
    """
    Handles a simple form submission, demonstrating input validation and CSRF protection.
    """
    form = MyForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data

        # Use email_validator library for robust email validation
        try:
            email_validator.validate_email(email)
        except email_validator.EmailNotValidError as e:
            logging.warning(f"Invalid email address: {email} - {str(e)}")
            abort(400, "Invalid email address.")

        logging.info(f"Form submitted successfully: Name={name}, Email={email}")
        # Process the data (e.g., store in a database)
        return f"Thank you, {name}! We received your email: {email}"

    return render_template('form.html', form=form)

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit errors."""
    logging.warning("Rate limit exceeded!")
    return "Rate limit exceeded. Please try again later.", 429

@app.errorhandler(400)
def bad_request_handler(e):
    """Handles 400 Bad Request errors."""
    logging.warning(f"Bad Request: {e}")
    return render_template('400.html', error=str(e)), 400

@app.errorhandler(500)
def internal_server_error_handler(e):
    """Handles 500 Internal Server Error."""
    logging.exception("Internal Server Error")  # Log the full exception
    return render_template('500.html'), 500

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Example rate limit for login
def login():
    """
    ***WARNING: This login example is for demonstration purposes ONLY and is HIGHLY INSECURE.  DO NOT use this code in a production environment.  It stores passwords in plaintext (in the original version) and is vulnerable to numerous attacks.  Use a proper authentication library like Flask-Login or Authlib with strong password hashing (e.g., bcrypt, Argon2).***
    """
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['logged_in'] = True
            session['username'] = username  # Store username in session
            logging.info(f"Successful login for user: {username}")
            return redirect(url_for('hello', username=username))
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return "Invalid username or password.", 401

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    """Redirects to the form example."""
    return redirect(url_for('form_example'))

if __name__ == '__main__':
    # Ensure HTTPS is used in production
    # Consider using a WSGI server like Gunicorn or uWSGI in production
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')

