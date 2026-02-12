import os
import secrets
import hashlib
import base64
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import configparser
from cryptography.fernet import Fernet
from flask_session import Session
import re  # For password validation
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)

# --- Configuration ---

# 1. Configuration using config.ini and fallback to environment variables
config = configparser.ConfigParser()
config.read('config.ini')

# Use environment variables if set, otherwise use config.ini values
DATABASE = os.environ.get('DATABASE_PATH', config['database']['path'])
FIRST_LOGIN_USERNAME = os.environ.get('FIRST_LOGIN_USERNAME', config['first_login']['username'])
FIRST_LOGIN_PASSWORD_KEY = os.environ.get('FIRST_LOGIN_PASSWORD_KEY', config['first_login']['password_key'])
encryption_key = os.environ.get('ENCRYPTION_KEY') # Encryption key can ONLY be set via environment variable for security

if not encryption_key:
    if 'encryption' in config and 'key' in config['encryption']:
        encryption_key = config['encryption']['key']
    else:
        raise ValueError("ENCRYPTION_KEY must be set either in config.ini or as an environment variable!")

# Ensure the encryption key is bytes
if isinstance(encryption_key, str):
    encryption_key = encryption_key.encode()

# Flask-Session configuration
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Flask-Limiter configuration
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# --- Database Connection ---

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# --- Encryption ---

cipher = Fernet(encryption_key)

def encrypt_data(data):
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(data):
    decrypted_data = cipher.decrypt(data.encode()).decode()
    return decrypted_data

# --- Password Hashing ---

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt.encode() + password.encode()
    hashed_password = hashlib.pbkdf2_hmac('sha256', salted_password, salt.encode(), 100000)
    return salt, base64.b64encode(hashed_password).decode('utf-8')

def verify_password(password, stored_hash, salt):
    new_salt, new_hash = hash_password(password, salt)
    return new_hash == stored_hash

# --- Password Strength Validation ---

def is_strong_password(password):
    if len(password) < 12:
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

# --- First Login Setup ---

def create_first_user():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the 'setup_complete' flag exists.  Create it if it doesn't.
    cursor.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'setup_complete' not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN setup_complete INTEGER DEFAULT 0")
        conn.commit()

    # Check if any users exist AND if setup is complete
    cursor.execute("SELECT COUNT(*) FROM users WHERE setup_complete = 1")
    setup_complete = cursor.fetchone()[0]

    if setup_complete == 0:
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if user_count == 0:
            # Hash the first login password
            first_login_password = config['first_login']['password'] # Get from config
            salt, password_hash = hash_password(first_login_password)

            # Create the first user
            cursor.execute("INSERT INTO users (username, password_hash, salt, setup_complete) VALUES (?, ?, ?, ?)",
                           (FIRST_LOGIN_USERNAME, password_hash, salt, 1)) # Mark setup complete
            conn.commit()
            print("First user created and setup complete flag set.")
        else:
            print("Users exist, but setup wasn't marked complete.  This shouldn't happen.")
    else:
        print("First-time setup already completed.")
    conn.close()

# --- Routes ---

@app.route('/')
def index():
    if not session.get("username"):
        return redirect("/login")
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not is_strong_password(password):
            return render_template('register.html', error='Password must be at least 12 characters long and contain uppercase, lowercase, numbers, and special characters.')

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check if the username already exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return render_template('register.html', error='Username already exists.')

        # Hash the password
        salt, password_hash = hash_password(password)

        # Insert the new user into the database
        cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, password_hash, salt))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))  # Redirect to login after successful registration

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user['password_hash']
            salt = user['salt']

            if verify_password(password, stored_hash, salt):
                session['username'] = username
                session.regenerate()  # Regenerate session ID
                return redirect(url_for('home'))
            else:
                return render_template('login.html', error='Invalid credentials')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/home')
def home():
    if not session.get("username"):
        return redirect("/login")

    return render_template('home.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# --- Main ---

if __name__ == '__main__':
    # Create the users table if it doesn't exist
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            setup_complete INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

    # Create the first user if none exist
    create_first_user()

    # Configure logging
    logging.basicConfig(level=logging.INFO)
    app.logger.addHandler(logging.StreamHandler())

    # Run the app (disable debug mode in production!)
    app.run(debug=False)

# --- Example config.ini ---
"""
[database]
path = instance/database.db

[first_login]
username = admin
password = VeryStrongPassword123!  ; Change this immediately!
password_key = mysecretkey

[encryption]
key = YOUR_ENCRYPTION_KEY  ; Store this securely!  Generate with Fernet.generate_key()
"""

# --- Instructions ---
"""
1.  Install dependencies: `pip install flask flask-session cryptography flask-limiter`
2.  Generate a Fernet encryption key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
3.  Create a `config.ini` file (outside the web root) with the database path, first login credentials, and the generated encryption key.  **IMPORTANT:  For production, set the ENCRYPTION_KEY environment variable instead of storing it in config.ini.**
4.  Run the application: `python your_app.py`
5.  Access the application in your browser.

You can also use environment variables to configure the application. For example:

DATABASE_PATH=/path/to/your/database.db
FIRST_LOGIN_USERNAME=admin
FIRST_LOGIN_PASSWORD_KEY=mysecretkey
ENCRYPTION_KEY=YOUR_ENCRYPTION_KEY

Then run the application: `python your_app.py`
"""

# --- Security Best Practices Summary ---
"""
*   Never store passwords in plain text. Always use a strong hashing algorithm like PBKDF2HMAC with a random salt.
*   Use parameterized queries to prevent SQL injection.
*   Store sensitive information (database credentials, API keys, encryption keys) in configuration files outside the web application's root directory *or* use environment variables.
*   Restrict access to configuration files using file system permissions.
*   Encrypt sensitive data at rest (if necessary).
*   Validate user input to prevent cross-site scripting (XSS) and other vulnerabilities. Implement robust password strength validation.
*   Use HTTPS to encrypt communication between the client and the server.
*   Keep your dependencies up to date to patch security vulnerabilities.  Run `pip check` regularly.
*   Implement proper authentication and authorization mechanisms.
*   Regularly review your code for security vulnerabilities.
*   Disable the first-time setup mechanism after the initial setup is complete.
*   Regenerate session IDs after successful login to prevent session fixation attacks.
*   Implement rate limiting to prevent brute-force attacks.
*   Disable `debug=True` in production and configure proper error logging.
"""

