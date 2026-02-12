import os
import hashlib
import secrets
from flask import Flask, request, render_template, redirect, url_for, session, abort
from functools import wraps
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman  # Import Flask-Talisman

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Configuration (ideally loaded from a separate file)
DATABASE_FILE = "users.db"
ADMIN_USERNAME = "admin"  # This is just a placeholder.  The first login will set the actual admin password.
MAX_LOGIN_ATTEMPTS = 5  # Maximum number of failed login attempts before lockout
LOCKOUT_DURATION = 60  # Lockout duration in seconds

# --- Logging ---
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Rate Limiting ---
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Example rate limits
)

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- Talisman (Security Headers) ---
# Configure Content Security Policy (CSP) - adjust as needed for your application
csp = {
    'default-src': '\'self\'',
    'script-src': '\'self\'',
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
}
talisman = Talisman(app, content_security_policy=csp, force_https=False) # force_https=False for local development


# --- Database Handling (Simple file-based for demonstration) ---
# In a real application, use a proper database like PostgreSQL or MySQL.

def create_user(username, password_hash, is_admin=False):
    """Creates a new user in the database."""
    try:
        with open(DATABASE_FILE, "a") as f:
            f.write(f"{username}:{password_hash}:{is_admin}\n")
        logging.info(f"User created: {username}")
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        return False
    return True

def get_user(username):
    """Retrieves a user from the database."""
    try:
        with open(DATABASE_FILE, "r") as f:
            for line in f:
                u, h, a = line.strip().split(":")
                if u == username:
                    return {"username": u, "password_hash": h, "is_admin": a == "True"}
        return None
    except FileNotFoundError:
        return None
    except Exception as e:
        logging.error(f"Error getting user: {e}")
        return None

def update_password(username, new_password_hash):
    """Updates a user's password in the database."""
    users = []
    try:
        with open(DATABASE_FILE, "r") as f:
            for line in f:
                u, h, a = line.strip().split(":")
                if u == username:
                    users.append(f"{u}:{new_password_hash}:{a}\n")
                else:
                    users.append(line)
    except FileNotFoundError:
        logging.warning(f"User not found during password update: {username}")
        return False  # User not found
    except Exception as e:
        logging.error(f"Error reading database during password update: {e}")
        return False

    try:
        with open(DATABASE_FILE, "w") as f:
            f.writelines(users)
        logging.info(f"Password updated for user: {username}")
        return True
    except Exception as e:
        logging.error(f"Error writing to database during password update: {e}")
        return False


def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = secrets.token_hex(16).encode('utf-8')  # Generate a random salt
    else:
        salt = salt.encode('utf-8')

    password_bytes = password.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, 100000)
    return f"{salt.decode('utf-8')}${key.hex()}"  # Store salt and hash


def verify_password(password, stored_hash):
    """Verifies the password against the stored hash."""
    salt, hash_value = stored_hash.split("$")
    computed_hash = hash_password(password, salt)
    return secrets.compare_digest(stored_hash, computed_hash)  # Constant-time comparison


# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        user = get_user(session['username'])
        if not user or not user['is_admin']:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function


# --- Input Validation ---
def is_valid_username(username):
    """Validates the username (alphanumeric and underscores only)."""
    pattern = r"^[a-zA-Z0-9_]+$"
    return bool(re.match(pattern, username))

def is_strong_password(password):
    """Checks for password complexity: min 8 chars, uppercase, lowercase, number, special char."""
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# --- Account Lockout ---
login_attempts = {}  # Dictionary to store login attempts per IP address
lockout_expiry = {} # Dictionary to store lockout expiry times

def is_account_locked(ip_address):
    """Checks if an account is locked based on IP address."""
    if ip_address in lockout_expiry:
        if lockout_expiry[ip_address] > time.time():
            return True
        else:
            # Lockout expired, remove from lockout_expiry
            del lockout_expiry[ip_address]
            return False
    return False

def record_failed_login(ip_address):
    """Records a failed login attempt for an IP address."""
    if ip_address in login_attempts:
        login_attempts[ip_address] += 1
    else:
        login_attempts[ip_address] = 1

    if login_attempts[ip_address] >= MAX_LOGIN_ATTEMPTS:
        lockout_expiry[ip_address] = time.time() + LOCKOUT_DURATION
        logging.warning(f"Account locked out for IP: {ip_address}")

def reset_login_attempts(ip_address):
    """Resets the login attempts for an IP address."""
    if ip_address in login_attempts:
        del login_attempts[ip_address]


# --- Routes ---
import time

@app.route('/login', methods=['GET'])
def login():
    """Displays the login form."""
    return render_template('login.html')


@app.route('/do_login', methods=['POST'])
@limiter.limit("5 per minute")  # Example rate limit for login
def do_login():
    """Handles the login attempt."""
    username = request.form.get('username')
    password = request.form.get('password')
    ip_address = get_remote_address()

    if is_account_locked(ip_address):
        remaining_time = int(lockout_expiry[ip_address] - time.time())
        return render_template('login.html', error=f"Account locked. Please try again in {remaining_time} seconds.")


    if not username or not password:
        return render_template('login.html', error="Username and password are required.")

    if not is_valid_username(username):
        return render_template('login.html', error="Invalid username format.")

    user = get_user(username)

    if user:
        if verify_password(password, user['password_hash']):
            session['username'] = username
            logging.info(f"User logged in: {username}")
            reset_login_attempts(ip_address) # Reset attempts on successful login
            if user['is_admin']:
                return redirect(url_for('admin_page'))
            else:
                return redirect(url_for('user_page')) # Redirect to a user page
        else:
            logging.warning(f"Invalid password attempt for user: {username}")
            record_failed_login(ip_address)
            return render_template('login.html', error="Invalid username or password.")
    else:
        # Check for first-time login for the admin user
        if username == ADMIN_USERNAME and not os.path.exists(DATABASE_FILE):
            # First-time admin setup.  Force password change.
            session['first_login'] = True
            session['username'] = ADMIN_USERNAME
            return redirect(url_for('set_admin_password'))
        else:
            logging.warning(f"Invalid username attempt: {username}")
            record_failed_login(ip_address)
            return render_template('login.html', error="Invalid username or password.")


@app.route('/set_admin_password', methods=['GET', 'POST'])
def set_admin_password():
    """Sets the admin password during the first login."""
    if not session.get('first_login') or session.get('username') != ADMIN_USERNAME:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            return render_template('set_admin_password.html', error="Password fields are required.")

        if new_password != confirm_password:
            return render_template('set_admin_password.html', error="Passwords do not match.")

        if not is_strong_password(new_password):
            return render_template('set_admin_password.html', error="Password must be at least 8 characters long and contain uppercase, lowercase, number and special character.")

        password_hash = hash_password(new_password)
        if create_user(ADMIN_USERNAME, password_hash, is_admin=True):
            del session['first_login']
            logging.info(f"Admin password set for the first time.")
            return redirect(url_for('login'))
        else:
            return render_template('set_admin_password.html', error="Failed to create admin user.")

    return render_template('set_admin_password.html')


@app.route('/admin_page')
@login_required
@admin_required
def admin_page():
    """Admin-only page."""
    return render_template('admin_page.html', username=session['username'])


@app.route('/user_page')
@login_required
def user_page():
    """User page."""
    return render_template('user_page.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    logging.info(f"User logged out: {session['username']}")
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Ensure the database file exists (or create it if it doesn't)
    if not os.path.exists(DATABASE_FILE):
        open(DATABASE_FILE, 'a').close()  # Create an empty file

    # Set session cookie attributes
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS

    app.run(debug=True)

