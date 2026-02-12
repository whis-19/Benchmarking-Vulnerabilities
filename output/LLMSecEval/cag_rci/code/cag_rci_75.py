from flask import Flask, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import bcrypt
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse, urljoin
import os
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key') # Use environment variable
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://user:password@host:port/database') # Use environment variable, default to postgresql
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Disable tracking for performance

# Secure Session Cookies
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_PERMANENT'] = True # Use permanent sessions
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30) # Set session timeout

db = SQLAlchemy(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Example User Model (using SQLAlchemy)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)  # Store password hash
    is_admin = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0) # Track failed attempts

    def __repr__(self):
        return f"User('{self.username}', '{self.is_admin}')"

# Example Login Route (using SQLAlchemy)
@app.route('/do_login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def do_login():
    """
    Handles the login process.
    """
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()  # Query the database

    if user:
        if user.failed_login_attempts >= 5: # Example lockout after 5 failed attempts
            flash("Account locked due to too many failed attempts. Please try again later.", "danger")
            logger.warning(f"Account locked for user {username} from {request.remote_addr} due to too many failed login attempts.")
            return redirect(url_for('login'))

        if bcrypt.check_password_hash(user.password, password):
            session['username'] = username
            flash("Login successful!", "success")
            logger.info(f"User {username} logged in successfully from {request.remote_addr}") # Log successful login

            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            db.session.commit()

            session.permanent = True # Make session permanent
            app.permanent_session_lifetime = timedelta(minutes=30) # Set session timeout
            session.modified = True # Ensure session is saved

            # Regenerate session ID after successful login
            session.regenerate()

            next_url = request.args.get('next')
            if next_url and is_safe_url(next_url):
                return redirect(next_url)
            else:
                return redirect(url_for('index'))
        else:
            flash("Invalid username or password.", "danger")
            logger.warning(f"Failed login attempt for user {username} from {request.remote_addr}") # Log failed login
            user.failed_login_attempts += 1
            db.session.commit()
            return redirect(url_for('login'))
    else:
        flash("Invalid username or password.", "danger")
        logger.warning(f"Failed login attempt for user {username} from {request.remote_addr}") # Log failed login
        return redirect(url_for('login'))

# Example Admin Required Decorator (using SQLAlchemy)
def admin_required(f):
    """
    Decorator to require admin access for a route.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        username = session.get('username')
        user = User.query.filter_by(username=username).first()
        if not user or not user.is_admin:
            logger.warning(f"Unauthorized access attempt to admin page by user {username} from {request.remote_addr}")
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Improved is_safe_url (using urlparse)
def is_safe_url(target):
    """
    Validates that the target URL is safe to redirect to.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == ref_url.netloc

# Example of logging an exception
try:
    # Some code that might raise an exception
    result = 10 / 0
except Exception as e:
    logger.error(f"An error occurred: {e}", exc_info=True) # Log the exception with traceback
    flash("An error occurred. Please try again.", "danger")
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True, host='0.0.0.0')

