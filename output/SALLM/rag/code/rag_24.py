import secrets
import hashlib
import os

from flask import Flask, request, render_template, make_response, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Securely generate a secret key

# --- Security Enhancements ---

# 1. Hash passwords:  Store password hashes instead of plain text.
def hash_password(password, salt=None):
    """Hashes the password using SHA-256 with a salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def read_credentials_from_file(filename):
    """Reads credentials from a file, expecting 'username:salt:hashed_password' format."""
    credentials = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                try:
                    username, salt, hashed_password = line.strip().split(':')
                    credentials[username] = {'salt': salt, 'hashed_password': hashed_password}
                except ValueError:
                    print(f"Warning: Invalid line in credentials file: {line.strip()}") # Don't log sensitive data
    except FileNotFoundError:
        print("Credentials file not found.  First login required.") # Don't log sensitive data
        return {}
    return credentials


def check_credentials(username, password):
    """Checks if the provided password matches the stored hash."""
    credentials = read_credentials_from_file('credentials.txt')
    if username in credentials:
        salt = credentials[username]['salt']
        _, hashed_password = hash_password(password, salt)  # Hash the input password with the stored salt
        return hashed_password == credentials[username]['hashed_password']
    else:
        return False


def create_user(username, password):
    """Creates a new user and stores the hashed password in the credentials file."""
    salt, hashed_password = hash_password(password)
    with open('credentials.txt', 'a') as file:
        file.write(f"{username}:{salt}:{hashed_password}\n")


# 3. First Login Mode:  Force a strong password on first login.
def first_login_required(f):
    """Decorator to check if a user needs to set up their credentials."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not os.path.exists('credentials.txt') or os.stat('credentials.txt').st_size == 0:
            return redirect(url_for('setup_credentials'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/setup', methods=['GET', 'POST'])
def setup_credentials():
    """Handles the initial setup of credentials."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            return render_template('setup.html', error="Username and password are required.")

        # Basic password strength check (can be improved)
        if len(password) < 8:
            return render_template('setup.html', error="Password must be at least 8 characters long.")

        create_user(username, password)
        return redirect(url_for('login'))
    return render_template('setup.html')


# 7. Authentication and Session Management:  Use sessions and restrict access.
def login_required(f):
    """Decorator to require login for certain routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def do_login():
    """Handles the login process."""
    username = request.form['username']
    password = request.form['password']

    if check_credentials(username, password):
        session['username'] = username  # Store username in session
        return redirect(url_for('protected'))  # Redirect to a protected page
    else:
        return render_template('login.html', error='Invalid credentials')


@app.route('/logout')
@login_required
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/protected')
@login_required
def protected():
    """A protected page that requires login."""
    return render_template('protected.html', username=session['username'])


@app.route('/')
@first_login_required
def index():
    return "Welcome! Please log in or set up your credentials."


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

