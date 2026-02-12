import os
import hashlib
import secrets
from flask import Flask, request, render_template, redirect, url_for, session, abort
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Securely generate a random secret key

# Configuration (ideally loaded from a separate file)
DATABASE_FILE = 'users.db'
ADMIN_USERNAME = 'admin'  # Not used directly, but for initial setup
CONFIG_FILE = 'config.ini' # File to store admin password hash

# --- Security Helper Functions ---

def hash_password(password, salt=None):
    """Hashes a password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = secrets.token_hex(16).encode('utf-8')  # Generate a random salt
    else:
        salt = salt.encode('utf-8')

    password_encoded = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_encoded, salt, 100000)
    return salt.decode('utf-8'), hashed_password.hex()


def verify_password(stored_salt, stored_hash, password):
    """Verifies a password against a stored hash and salt."""
    salt = stored_salt.encode('utf-8')
    password_encoded = password.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac('sha256', password_encoded, salt, 100000)
    return hashed_password.hex() == stored_hash


def requires_auth(f):
    """Decorator to require authentication for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def requires_admin(f):
    """Decorator to require admin privileges for a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session or session['username'] != ADMIN_USERNAME:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated


# --- Database/Configuration Handling (Simplified) ---

def create_admin_user(password):
    """Creates the initial admin user and stores the hashed password."""
    salt, hashed_password = hash_password(password)
    with open(CONFIG_FILE, 'w') as f:
        f.write(f"admin_salt={salt}\n")
        f.write(f"admin_hash={hashed_password}\n")


def load_admin_credentials():
    """Loads the admin credentials from the configuration file."""
    try:
        with open(CONFIG_FILE, 'r') as f:
            lines = f.readlines()
            admin_salt = None
            admin_hash = None
            for line in lines:
                if line.startswith("admin_salt="):
                    admin_salt = line.split("=")[1].strip()
                elif line.startswith("admin_hash="):
                    admin_hash = line.split("=")[1].strip()
            if admin_salt and admin_hash:
                return admin_salt, admin_hash
            else:
                return None, None
    except FileNotFoundError:
        return None, None


def user_exists(username):
    """Placeholder for checking if a user exists in the database."""
    # In a real application, this would query the database.
    # For simplicity, we only check for the admin user.
    admin_salt, admin_hash = load_admin_credentials()
    return username == ADMIN_USERNAME and admin_salt is not None and admin_hash is not None


# --- Routes ---

@app.route('/login', methods=['GET'])
def login():
    """Displays the login form."""
    return render_template('login.html')


@app.route('/do_login', methods=['POST'])
def do_login():
    """Handles the login attempt."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('login.html', error='Username and password are required.')

    admin_salt, admin_hash = load_admin_credentials()

    if username == ADMIN_USERNAME and admin_salt and admin_hash:
        if verify_password(admin_salt, admin_hash, password):
            session['username'] = username
            return redirect(url_for('admin_page'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    else:
        return render_template('login.html', error='Invalid username or password.')


@app.route('/first_login', methods=['GET', 'POST'])
def first_login():
    """Handles the first login and admin password setup."""
    if os.path.exists(CONFIG_FILE):
        return "Admin user already configured."

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not password or not confirm_password:
            return render_template('first_login.html', error='Password and confirmation are required.')

        if password != confirm_password:
            return render_template('first_login.html', error='Passwords do not match.')

        create_admin_user(password)
        return redirect(url_for('login'))  # Redirect to login after setup

    return render_template('first_login.html')


@app.route('/admin_page')
@requires_admin
def admin_page():
    """Admin-only page."""
    return render_template('admin_page.html', username=session['username'])


@app.route('/logout')
@requires_auth
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/')
def index():
    """Redirects to login if not authenticated."""
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Check if the admin user is already set up.  If not, redirect to first_login.
    if not os.path.exists(CONFIG_FILE):
        print("Admin user not configured.  Please visit /first_login to set up the admin password.")
    app.run(debug=True, host='0.0.0.0', port=5000)

