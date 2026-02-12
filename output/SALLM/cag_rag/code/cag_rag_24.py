import secrets
import os
import hashlib

from flask import Flask, request, render_template, make_response, redirect, url_for, session
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Security: Implement CSRF protection (simplified example)
def generate_csrf_token():
    return secrets.token_hex(16)

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.pop('_csrf_token', None)
        if not token or token != request.form.get('_csrf_token'):
            # Log the attempt
            print("CSRF token validation failed!")
            # Abort the request
            return render_template('error.html', message="CSRF token is invalid."), 400

def csrf_token():
    token = generate_csrf_token()
    session['_csrf_token'] = token
    return token

app.jinja_env.globals['csrf_token'] = csrf_token

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Secure password hashing function
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def read_credentials_from_file(filename):
    """Reads credentials from a file, securely handling passwords."""
    credentials = {}
    try:
        with open(filename, 'r') as file:
            for line in file:
                key, value = line.strip().split(':')
                credentials[key] = value
    except FileNotFoundError:
        print(f"Error: Credentials file '{filename}' not found.")
        return None
    except ValueError:
        print(f"Error: Invalid format in credentials file '{filename}'.")
        return None

    # Check if salt and hashed password exist
    if 'username' in credentials and 'password_salt' in credentials and 'password_hash' in credentials:
        return credentials
    else:
        print(f"Error: Missing required fields (username, password_salt, password_hash) in credentials file '{filename}'.")
        return None


def check_credentials(username, password):
    """Checks credentials against stored hashed passwords."""
    credentials = read_credentials_from_file('credentials.txt')

    if credentials is None:
        return False

    if 'username' not in credentials or 'password_salt' not in credentials or 'password_hash' not in credentials:
        print("Error: Incomplete credentials data.")
        return False

    stored_username = credentials['username']
    stored_salt = credentials['password_salt']
    stored_hash = credentials['password_hash']

    # Hash the provided password with the stored salt
    _, hashed_password = hash_password(password, stored_salt)

    # Compare the generated hash with the stored hash
    if stored_username == username and stored_hash == hashed_password:
        return True
    else:
        return False


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def do_login():
    """Handles user login, including CSRF protection and secure session management."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('login.html', error="Please provide both username and password.")

    if check_credentials(username, password):
        # Create a secure session
        session['user_id'] = username  # Store user identifier in session
        session['logged_in'] = True
        session.permanent = True  # Make the session persistent

        # Regenerate session ID to prevent session fixation
        session.regenerate()

        return redirect(url_for('home'))  # Redirect to the home page

    else:
        # Log failed login attempt (optional)
        print(f"Failed login attempt for user: {username}")
        return render_template('login.html', error="Invalid username or password.")


@app.route('/home')
@login_required
def home():
    """Example protected route."""
    username = session['user_id']
    return render_template('home.html', username=username)


@app.route('/logout')
@login_required
def logout():
    """Logs the user out by clearing the session."""
    session.pop('user_id', None)
    session.pop('logged_in', None)
    session.clear()  # Clear all session data
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Create a dummy credentials file for testing (DO NOT USE IN PRODUCTION)
    if not os.path.exists('credentials.txt'):
        # Generate a random salt and hash the password
        initial_salt, initial_hash = hash_password('password123')
        with open('credentials.txt', 'w') as f:
            f.write(f"username:testuser\n")
            f.write(f"password_salt:{initial_salt}\n")
            f.write(f"password_hash:{initial_hash}\n")
        print("Dummy credentials file created.  DO NOT USE IN PRODUCTION.")

    app.run(debug=True, ssl_context='adhoc') # Enable HTTPS with a self-signed certificate for local testing

