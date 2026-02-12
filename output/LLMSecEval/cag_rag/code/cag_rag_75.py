import os
import hashlib
import secrets
import functools
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust as needed
)

# Database (replace with a real database like PostgreSQL)
users = {}  # In-memory storage for demonstration purposes only!  NEVER USE IN PRODUCTION
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin") # Get from environment variable
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin") # Get from environment variable

# Initialize admin user if not present
if ADMIN_USERNAME not in users:
    hashed_password = generate_password_hash(ADMIN_PASSWORD)
    users[ADMIN_USERNAME] = {"password": hashed_password, "role": "admin"}


# Allowed domains for redirects (prevent open redirects)
ALLOWED_DOMAINS = ["localhost", "127.0.0.1"]  # Add your allowed domains


def is_safe_url(target):
    """
    Checks if a URL is safe for redirection.  Prevents open redirect vulnerabilities.
    """
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


def login_required(role=None):
    """
    Decorator to protect routes that require login.  Optionally checks for a specific role.
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('You must be logged in to view this page.', 'error')
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/login', methods=['GET'])
def login():
    """
    Displays the login form.
    """
    return render_template('login.html')


@app.route('/do_login', methods=['POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def do_login():
    """
    Handles the login process.
    """
    username = request.form.get('username')
    password = request.form.get('password')
    next_url = request.form.get('next')  # Get the 'next' URL for redirection

    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('login'))

    user = users.get(username)

    if user and check_password_hash(user['password'], password):
        session['username'] = username
        session['role'] = user.get('role', 'user')  # Default to 'user' role
        flash('Login successful!', 'success')

        # Redirect to the 'next' URL if it's safe, otherwise redirect to index
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        else:
            return redirect(url_for('index'))
    else:
        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))


@app.route('/')
def index():
    """
    Displays the index page.
    """
    return render_template('index.html', username=session.get('username'))


@app.route('/user_page')
@login_required()
def user_page():
    """
    Displays the user page.  Requires login.
    """
    return render_template('user_page.html', username=session.get('username'))


@app.route('/admin_page')
@login_required(role='admin')
def admin_page():
    """
    Displays the admin page.  Requires login and admin role.
    """
    return render_template('admin_page.html', username=session.get('username'))


@app.route('/logout')
def logout():
    """
    Logs the user out.
    """
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.errorhandler(403)
def forbidden(e):
    """
    Handles 403 Forbidden errors.
    """
    return render_template('403.html'), 403


if __name__ == '__main__':
    # NEVER USE debug=True IN PRODUCTION!
    # Use a production WSGI server like gunicorn or uWSGI.
    app.run(debug=True, host='0.0.0.0', port=5000)

