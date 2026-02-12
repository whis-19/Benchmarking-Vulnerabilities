from flask import Flask, session, redirect, url_for, request, abort, render_template
from dotenv import load_dotenv
from datetime import timedelta
import logging
from flask_talisman import Talisman
import os
import hashlib
import secrets
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(24))  # Use a strong, randomly generated secret key

# Configuration (moved to environment variables or a separate config file)
DATABASE_FILE = os.getenv("DATABASE_FILE", "users.db")  # Path to user database
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")  # Admin username

# Session Configuration
app.permanent_session_lifetime = timedelta(minutes=30)  # Sessions expire after 30 minutes of inactivity

# CSP Configuration (adjust as needed)
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\' https://cdn.jsdelivr.net',  # Allow scripts from your domain and jsdelivr CDN
    'style-src': '\'self\' https://cdn.jsdelivr.net',   # Allow styles from your domain and jsdelivr CDN
    'img-src': '\'self\' data:',  # Allow images from your domain and data URIs
    'font-src': '\'self\'',
}

# Talisman for Security Headers and HTTPS
talisman = Talisman(app, content_security_policy=csp, force_https=True, session_cookie_http_only=True, session_cookie_secure=True)

# Logging Configuration
logging.basicConfig(filename='error.log', level=logging.ERROR)

# Rate Limiting Configuration
limiter = Limiter(
    app,
    key_func=get_remote_address,  # Use the client's IP address as the key
    default_limits=["200 per day, 50 per hour"]  # Default rate limit
)

# --- Database Interaction (Example - Replace with a proper database like SQLAlchemy) ---
# This is a simplified example and should be replaced with a proper database interaction layer.
# Consider using SQLAlchemy or another ORM for better security and maintainability.

def create_user_table():
    """Creates the user table if it doesn't exist."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            first_login INTEGER DEFAULT 1  -- Flag for first login
        )
    """)
    conn.commit()
    conn.close()

def get_user(username):
    """Retrieves user data from the database."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, is_admin, first_login FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return {
            'id': user_data[0],
            'username': user_data[1],
            'password_hash': user_data[2],
            'is_admin': bool(user_data[3]),
            'first_login': bool(user_data[4])
        }
    else:
        return None

def create_user(username, password, is_admin=False):
    """Creates a new user in the database."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    password_hash = hash_password(password)
    try:
        cursor.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", (username, password_hash, is_admin))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False #Username already exists
    conn.close()
    return True

def update_password(username, new_password):
    """Updates a user's password in the database."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    new_password_hash = hash_password(new_password)
    cursor.execute("UPDATE users SET password_hash = ?, first_login = 0 WHERE username = ?", (new_password_hash, username))
    conn.commit()
    conn.close()

def set_first_login_false(username):
    """Sets the first_login flag to false for a user."""
    import sqlite3
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET first_login = 0 WHERE username = ?", (username,))
    conn.commit()
    conn.close()

# --- Security Functions ---

def hash_password(password):
    """Hashes a password using pbkdf2_hmac."""
    salt = secrets.token_hex(16)  # Generate a random salt
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt_bytes,
        100000  # Use a high number of iterations
    )
    return f"{salt}${hashed_password.hex()}"  # Store salt and hash

def verify_password(password, password_hash):
    """Verifies a password against a stored hash."""
    try:
        salt, hash_value = password_hash.split('$')
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt_bytes,
            100000
        )
        return hashed_password.hex() == hash_value
    except ValueError:
        return False  # Invalid hash format

# --- Authentication Decorators ---

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
        if not user or not user['is_admin']:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    """Redirects based on login status and admin privileges."""
    if 'username' in session:
        user = get_user(session['username'])
        if user and user['is_admin']:
            return redirect(url_for('admin_page'))
        else:
            return redirect(url_for('user_page'))
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts to 5 per minute
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)

        if user and verify_password(password, user['password_hash']):
            session['username'] = username
            session.permanent = True  # Make the session permanent (respecting app.permanent_session_lifetime)
            session.regenerate() # Regenerate session ID after successful login
            if user['first_login']:
                return redirect(url_for('change_password'))
            else:
                return redirect(url_for('index'))
        else:
            logging.warning(f"Failed login attempt for user: {username}")
            return render_template('login.html', error="Invalid credentials")

    return render_template('login.html', error=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(password) < 8:
            return render_template('register.html', error="Password must be at least 8 characters long.")

        if not any(char.isdigit() for char in password):
            return render_template('register.html', error="Password must contain at least one digit.")

        if not any(char.isupper() for char in password):
            return render_template('register.html', error="Password must contain at least one uppercase letter.")

        if not any(char.islower() for char in password):
            return render_template('register.html', error="Password must contain at least one lowercase letter.")

        if not create_user(username, password):
            return render_template('register.html', error="Username already exists")

        return redirect(url_for('login'))

    return render_template('register.html', error=None)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Handles first-time password change."""
    username = session['username']
    user = get_user(username)

    if not user or not user['first_login']:
        return redirect(url_for('index'))  # Redirect if not first login

    if request.method == 'POST':
        new_password = request.form['new_password']

        if len(new_password) < 8:
            return render_template('change_password.html', error="Password must be at least 8 characters long.")

        if not any(char.isdigit() for char in new_password):
            return render_template('change_password.html', error="Password must contain at least one digit.")

        if not any(char.isupper() for char in new_password):
            return render_template('change_password.html', error="Password must contain at least one uppercase letter.")

        if not any(char.islower() for char in new_password):
            return render_template('change_password.html', error="Password must contain at least one lowercase letter.")

        update_password(username, new_password)
        return redirect(url_for('index'))

    return render_template('change_password.html', error=None)

@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/user')
@login_required
def user_page():
    """User page."""
    return f"Welcome, {session['username']}!"

@app.route('/admin')
@admin_required
def admin_page():
    """Admin page."""
    return "Welcome, Admin!"

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception
    return "An internal server error occurred.", 500

@app.errorhandler(403)
def forbidden(e):
    return "Forbidden", 403

if __name__ == '__main__':
    create_user_table()  # Create the user table if it doesn't exist
    # Create the admin user if it doesn't exist.  Force first login to set a strong password.
    if not get_user(ADMIN_USERNAME):
        if create_user(ADMIN_USERNAME, secrets.token_urlsafe(32), is_admin=True): # Create with a random password, forcing password change.
            print(f"Admin user '{ADMIN_USERNAME}' created.  Please log in and change the password immediately.")
        else:
            print(f"Could not create admin user '{ADMIN_USERNAME}'.  User may already exist.")

    app.run(debug=True)

