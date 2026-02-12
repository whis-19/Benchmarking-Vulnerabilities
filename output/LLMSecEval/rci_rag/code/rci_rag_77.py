import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
import secrets
import logging
import passlib.hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask import g  # Import g for database connection context
from flask_talisman import Talisman
from wtforms import Form, StringField, PasswordField, EmailField, validators
import re
from urllib.parse import urlparse, urljoin
from flask import request as flask_request
from functools import wraps

app = Flask(__name__)

# --- Security Configuration ---
# Securely generate a secret key
app.secret_key = secrets.token_hex(16)

# Configure logging (important for security audits, but avoid logging sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production (e.g., Redis)
)

# CSRF Protection
csrf = CSRFProtect(app)

# Security Headers with Flask-Talisman
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': '\'self\'',
        'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', '\'nonce-{{ csp_nonce() }}\''],  # Example: Allow scripts from CDN, use nonces for inline scripts
        'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow styles from CDN
        'img-src': '\'self\' data:',
        'font-src': ['\'self\'', 'https://cdn.jsdelivr.net'],
    },
    content_security_policy_nonce_in=['script-src'],
    force_https=True,  # Enforce HTTPS
    session_cookie_secure=True,  # Secure session cookie
    session_cookie_httponly=True,  # HTTPOnly session cookie
    strict_transport_security=True,  # HSTS
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_include_subdomains=True,
    frame_options='DENY',  # Use DENY if framing is not needed
    content_type_nosniff=True,
    x_xss_protection=True
)

# --- Database Configuration ---
DATABASE = os.path.join(app.root_path, 'user_data.db')  # Absolute path outside web root

# --- Database Helper Functions ---
def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = sqlite3.connect(DATABASE)
        g.sqlite_db.row_factory = sqlite3.Row
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()
    print('Initialized the database.')

# --- Password Hashing Functions ---
def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = passlib.hash.bcrypt.hash(password)
    return hashed_password

def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    return passlib.hash.bcrypt.verify(password, hashed_password)

# --- Authentication Functions ---
def authenticate_user(username, password):
    """Authenticates a user against the database."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            hashed_password = result['password']
            if verify_password(password, hashed_password):
                return True
        return False
    except sqlite3.Error as e:
        logging.error(f"Authentication error: {e}")
        return False

# --- User Management Functions ---
def create_user(username, password, email):
    """Creates a new user in the database."""
    db = get_db()
    cursor = db.cursor()
    try:
        hashed_password = hash_password(password)
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                       (username, hashed_password, email))  # Email is no longer encrypted
        db.commit()
        return True
    except sqlite3.IntegrityError:
        flash("Username already exists.", "error")
        return False
    except sqlite3.Error as e:
        logging.error(f"User creation error: {e}")
        flash("An error occurred during user creation.", "error")
        return False

def get_user_email(username):
    """Retrieves the user's email from the database."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            return result['email']
        return None
    except sqlite3.Error as e:
        logging.error(f"Error retrieving email: {e}")
        return None

def update_email(username, new_email, password):
    """Updates the user's email in the database after verifying credentials."""
    db = get_db()
    cursor = db.cursor()
    try:
        # Verify password
        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result or not verify_password(password, result['password']):
            flash("Incorrect password.", "error")
            return False

        cursor.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, username))
        db.commit()
        return True
    except sqlite3.Error as e:
        logging.error(f"Email update error: {e}")
        flash("An error occurred during email update.", "error")
        return False

# --- WTForms ---
class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25),
                                       validators.Regexp(r'^[a-zA-Z0-9_]+$', message='Username must be alphanumeric or underscore'),
                                       validators.NoneOf(['admin', 'administrator'], message='Username not allowed')])
    email = EmailField('Email Address', [validators.Email()])
    password = PasswordField('Password', [
        validators.Length(min=8),
        validators.EqualTo('confirm', message='Passwords must match'),
        validators.Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,}$',
                          message='Password must contain at least 8 characters, including one uppercase letter, one lowercase letter, one number, and one special character.')
    ])
    confirm = PasswordField('Repeat Password')

class ChangeEmailForm(Form):
    new_email = EmailField('New Email Address', [validators.Email()])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired()])

class LoginForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

# --- Safe Redirect ---
def is_safe_url(target):
    ref_url = urlparse(flask_request.host_url)
    test_url = urlparse(urljoin(flask_request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

def get_redirect_target():
    for target in flask_request.args.get('next'), flask_request.referrer:
        if target:
            if is_safe_url(target):
                return target
    return url_for('index')

def redirect_back():
    target = flask_request.args.get('next')
    if not target or not is_safe_url(target):
        target = url_for('index')
    return redirect(target)

# --- Account Lockout ---
failed_login_attempts = {}  # Store failed login attempts per IP address
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 60  # seconds

def is_locked_out(ip_address):
    if ip_address in failed_login_attempts:
        attempts, timestamp = failed_login_attempts[ip_address]
        if attempts >= LOCKOUT_THRESHOLD and (time.time() - timestamp) < LOCKOUT_DURATION:
            return True
    return False

def record_failed_login(ip_address):
    if ip_address in failed_login_attempts:
        attempts, timestamp = failed_login_attempts[ip_address]
        failed_login_attempts[ip_address] = (attempts + 1, time.time())
    else:
        failed_login_attempts[ip_address] = (1, time.time())

def clear_failed_login(ip_address):
    if ip_address in failed_login_attempts:
        del failed_login_attempts[ip_address]

import time

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        email = form.email.data

        if create_user(username, password, email):
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            return render_template('register.html', form=form)  # Keep them on the registration page with error messages
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm(request.form)
    ip_address = get_remote_address()

    if is_locked_out(ip_address):
        flash(f"Too many failed login attempts. Account locked for {LOCKOUT_DURATION} seconds.", "error")
        return render_template('login.html', form=form)

    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data

        if authenticate_user(username, password):
            session['username'] = username
            session.regenerate()  # Regenerate session ID
            flash('Login successful!', 'success')
            clear_failed_login(ip_address)
            next_url = get_redirect_target()
            return redirect(next_url)
        else:
            record_failed_login(ip_address)
            flash('Invalid username or password.', 'error')
            return render_template('login.html', form=form)
    return render_template('login.html', form=form)

@app.route('/profile')
def profile():
    if 'username' in session:
        username = session['username']
        email = get_user_email(username)
        return render_template('profile.html', username=username, email=email)
    else:
        return redirect(url_for('login'))

@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'username' in session:
        form = ChangeEmailForm(request.form)
        if request.method == 'POST' and form.validate():
            username = session['username']
            new_email = form.new_email.data
            confirm_password = form.confirm_password.data

            if update_email(username, new_email, confirm_password):
                flash('Email updated successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                return render_template('change_email.html', form=form) # Stay on the page with error messages
        return render_template('change_email.html', form=form)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

# --- First Login Mode ---
def check_first_login():
    """Checks if any users exist in the database. If not, redirects to a setup page."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    return count == 0

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Handles the first-time setup of the application."""
    if not check_first_login():
        return redirect(url_for('login'))  # Redirect if not the first login

    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = form.password.data
        email = form.email.data

        if create_user(username, password, email):
            flash('Setup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            return render_template('setup.html', form=form)
    return render_template('setup.html', form=form)

@app.before_request
def before_request():
    """Redirect to setup if it's the first login."""
    if request.endpoint not in ('setup', 'static') and check_first_login():
        return redirect(url_for('setup'))

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 error: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"500 error: {e}")
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

