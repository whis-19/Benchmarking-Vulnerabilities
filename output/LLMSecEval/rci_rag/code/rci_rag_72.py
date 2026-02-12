import os
import bcrypt
from flask import Flask, render_template, request, session, redirect, url_for, abort, flash
from functools import wraps
import secrets
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_session import Session  # For server-side session storage
import json  # For structured logging

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = secrets.token_hex(24)  # Generate a strong, random secret key

# Session Configuration (Server-Side)
app.config['SESSION_TYPE'] = 'filesystem'  # Or 'redis', 'mongodb', etc.
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
app.config['SESSION_USE_SIGNER'] = True  # Securely sign the session cookie
app.config['SESSION_KEY_PREFIX'] = 'sess:'  # Prefix for session keys
app.config['SESSION_FILE_DIR'] = 'flask_session' # Directory to store session files
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF
Session(app)

# Database Configuration (Example - replace with a real database)
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    # Fallback to a file-based database for development
    DATABASE_URL = "sqlite:///./database.db"
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Suppress warning
    print("WARNING: Using SQLite for database.  Not suitable for production.")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

# Initialize SQLAlchemy (if using)
# from flask_sqlalchemy import SQLAlchemy
# db = SQLAlchemy(app)

# Configure logging (important for security audits, but avoid logging sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)  # Get a logger instance

# Hashing function (use a strong hashing algorithm like bcrypt or scrypt in production)
def hash_password(password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')  # Store as string

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to view this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Input Validation Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["20 per minute"],  # Adjust as needed
    storage_uri="memory://" # Use a more robust storage for production (Redis, etc.)
)

# CSP Nonce Generation
def generate_csp_nonce():
    return secrets.token_hex(16)

@app.context_processor
def inject_csp_nonce():
    return {'csp_nonce': generate_csp_nonce}

# Security Headers
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': ['\'self\'', '\'nonce-{{ csp_nonce() }}\''],
        'style-src': ['\'self\'', '\'nonce-{{ csp_nonce() }}\''],
        'img-src': ['\'self\'', 'data:'],
        'font-src': '\'self\'',
        'report-uri': '/csp_report',  # Replace with your reporting endpoint
    },
    content_security_policy_nonce_in=['script-src', 'style-src'],
    force_https=True,  # Enforce HTTPS
    session_cookie_secure=True, # Ensure session cookie is only sent over HTTPS
    session_cookie_http_only=True, # Prevent JavaScript access to session cookie
)

@app.route('/csp_report', methods=['POST'])
def csp_report():
    report = request.get_json()
    logger.warning(f"CSP Violation: {json.dumps(report)}")
    # In a real application, you would store this report in a database
    return '', 204

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Limit registration attempts
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Input Sanitization (Example - use a library like bleach for more robust sanitization)
        username = username.replace("<", "&lt;").replace(">", "&gt;") # Basic XSS protection

        # Check if username exists (replace with database query)
        # if db.session.query(User).filter_by(username=username).first():
        if username in DATABASE:
            flash('Username already exists. Please choose a different one.')
            return render_template('register.html', form=form)

        hashed_password = hash_password(password)
        DATABASE[username] = hashed_password # Replace with database insert
        flash('Registration successful! Please log in.')
        logger.info(json.dumps({"event": "user_registered", "username": username}))
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute") # Limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Input Sanitization (Example)
        username = username.replace("<", "&lt;").replace(">", "&gt;")

        # Replace with database query
        # user = db.session.query(User).filter_by(username=username).first()
        if username in DATABASE:
            stored_hash = DATABASE[username] # Replace with database retrieval
            if check_password(password, stored_hash):
                session['username'] = username
                session.regenerate() # Prevent session fixation
                logger.info(json.dumps({"event": "user_logged_in", "username": username}))
                return redirect(url_for('secret'))
            else:
                flash('Invalid username or password.')
                logger.warning(json.dumps({"event": "failed_login", "username": username, "ip_address": get_remote_address()}))
        else:
            flash('Invalid username or password.')
            logger.warning(json.dumps({"event": "failed_login", "username": username, "ip_address": get_remote_address()}))

    return render_template('login.html', form=form)

@app.route('/secret')
@login_required
def secret():
    # Access control enforced by the login_required decorator
    # Only authenticated users can access this page
    return render_template('secret.html')

@app.route('/logout')
@login_required
def logout():
    username = session.get('username')
    session.pop('username', None)
    logger.info(json.dumps({"event": "user_logged_out", "username": username}))
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    logger.error(f"Internal Server Error: {error}") # Log the error
    return render_template('500.html'), 500 # Display a generic error page

if __name__ == '__main__':
    # Never run in debug mode in production!
    app.run(debug=False, host='0.0.0.0', port=5000)

