from flask import Flask, request, redirect, url_for, session, abort
import os
import secrets
import hashlib
import sqlite3
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
import re  # For password complexity
import logging
from flask_talisman import Talisman

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['DATABASE'] = os.getenv('DATABASE_PATH', 'users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{app.config['DATABASE']}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Suppress warning
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Only set to True if using HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Recommended setting
app.permanent_session_lifetime = timedelta(minutes=30)

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

db = SQLAlchemy(app)

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Content Security Policy
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
    'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'],   # Example: Allow styles from a CDN
    'img-src': ['\'self\'', 'data:'],  # Allow images from self and data URIs
}

talisman = Talisman(app, content_security_policy=csp)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    is_admin = db.Column(db.Integer, default=0)
    first_login = db.Column(db.Integer, default=1)

    def __repr__(self):
        return f'<User {self.username}>'

# Database Functions
def get_db():
    """Connects to the database."""
    # SQLAlchemy handles connection management, so this function is no longer needed.
    return db

def create_user_table():
    """Creates the user table if it doesn't exist."""
    with app.app_context():
        db.create_all()

def get_user(username):
    """Retrieves a user from the database."""
    with app.app_context():
        return User.query.filter_by(username=username).first()

def create_user(username, password, is_admin=0, first_login=1):
    """Creates a new user in the database."""
    salt = secrets.token_hex(16)
    hashed_password = hash_password(password, salt)
    with app.app_context():
        user = User(username=username, password=hashed_password, salt=salt, is_admin=is_admin, first_login=first_login)
        db.session.add(user)
        db.session.commit()

def update_password(username, new_password):
    """Updates a user's password in the database."""
    salt = secrets.token_hex(16)
    hashed_password = hash_password(new_password, salt)
    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = hashed_password
            user.salt = salt
            user.first_login = 0
            db.session.commit()

def hash_password(password, salt):
    """Hashes the password using PBKDF2-HMAC."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', salted_password, salt.encode('utf-8'), 100000)
    return hashed_password.hex()

# Decorators
def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        user = get_user(session['username'])
        if not user or not user.is_admin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.before_request
def before_request():
    """Redirect HTTP to HTTPS."""
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

@app.route('/')
@login_required
def index():
    """Home page."""
    return f"<h1>Welcome, {session['username']}!</h1> <a href='/logout'>Logout</a>"

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)

        if user and hash_password(password, user.salt) == user.password:
            session['username'] = username
            session.permanent = True
            session.regenerate() # Regenerate session ID after login
            logging.info(f"User {username} logged in successfully from {request.remote_addr}.") # Log successful login
            if user.first_login:
                return redirect(url_for('change_password'))
            return redirect(url_for('index'))
        else:
            logging.warning(f"Failed login attempt for user {username} from {request.remote_addr}.") # Log failed login
            return "Invalid credentials", 401

    return """
        <h1>Login</h1>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    """

@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/admin')
@admin_required
def admin():
    """Admin-only page."""
    return "<h1>Admin Area</h1>"

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Handles first-time password change."""
    username = session['username']
    user = get_user(username)

    if not user or not user.first_login:
        return redirect(url_for('index'))  # Redirect if not first login

    if request.method == 'POST':
        new_password = request.form['new_password']

        # Password complexity check
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]).{8,}$", new_password):
            return "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.", 400

        update_password(username, new_password)
        return redirect(url_for('index'))

    return """
        <h1>First Login: Change Your Password</h1>
        <form method="post">
            <input type="password" name="new_password" placeholder="New Password" required>
            <button type="submit">Change Password</button>
        </form>
    """

if __name__ == '__main__':
    create_user_table()
    # Create an admin user if one doesn't exist
    with app.app_context():
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            create_user('admin', 'P@$$wOrd123!', is_admin=1, first_login=1) # Default admin password, will be forced to change
    app.run(debug=True, host='0.0.0.0', port=5000)

