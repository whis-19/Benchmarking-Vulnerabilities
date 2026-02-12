import secrets
import os
from flask import Flask, request, render_template, make_response, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Generate a secure random key for the session
app.secret_key = secrets.token_hex(32)

# Ensure the credentials file exists and has proper permissions
CREDENTIALS_FILE = 'credentials.txt'

# Create the credentials file if it doesn't exist
if not os.path.exists(CREDENTIALS_FILE):
    # Generate a random username and password
    default_username = 'admin'
    default_password = secrets.token_urlsafe(16)  # Generate a strong random password
    hashed_password = generate_password_hash(default_password)

    with open(CREDENTIALS_FILE, 'w') as f:
        f.write(f'username:{default_username}\n')
        f.write(f'password:{hashed_password}\n')

    # Set file permissions to restrict access (Unix-like systems)
    try:
        os.chmod(CREDENTIALS_FILE, 0o600)  # Owner read/write only
    except OSError:
        print(f"Warning: Could not set file permissions on {CREDENTIALS_FILE}.  Ensure only the web server user can read this file.")

    print(f"Credentials file '{CREDENTIALS_FILE}' created with default username '{default_username}' and a randomly generated password.  Please change these credentials immediately.")
    print(f"Default password: {default_password}")  # Display the generated password ONCE.  Remove this in production.


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


def read_credentials_from_file(filename):
    """Reads credentials from a file, handling potential errors."""
    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            credentials = {}
            for line in lines:
                key, value = line.strip().split(':', 1)  # Split only once
                credentials[key] = value
            return credentials
    except FileNotFoundError:
        print(f"Error: Credentials file '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error reading credentials from file: {e}")
        return None


def check_credentials(username, password):
    """Checks credentials against those stored in the file, using password hashing."""
    credentials = read_credentials_from_file(CREDENTIALS_FILE)
    if credentials is None:
        return False

    stored_username = credentials.get('username')
    stored_password_hash = credentials.get('password')

    if not stored_username or not stored_password_hash:
        print("Error: Invalid credentials file format.  Missing username or password hash.")
        return False

    if stored_username == username and check_password_hash(stored_password_hash, password):
        return True
    else:
        return False


@app.route('/login', methods=['POST'])
def do_login():
    """Handles login attempts, creating a session on successful authentication."""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        return render_template('login.html', error='Please enter both username and password.')

    if check_credentials(username, password):
        # Create a session
        session['username'] = username
        return redirect(url_for('protected'))  # Redirect to a protected page
    else:
        return render_template('login.html', error='Invalid username or password.')


@app.route('/protected')
def protected():
    """A protected route that requires a valid session."""
    if 'username' in session:
        return f"Logged in as {session['username']}"
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out by clearing the session."""
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Enable SSL for local testing.  NEVER use adhoc in production.

