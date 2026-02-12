import hashlib
import os
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session
from cryptography.fernet import Fernet
import configparser
import bleach  # For sanitization
import stat  # For file permission checking
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
import cryptography

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)  # Handle X-Forwarded-For headers correctly
app.secret_key = os.urandom(24)  # Securely generate a random secret key

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production (e.g., redis://)
)

# Configuration loading
config = configparser.ConfigParser()

# --- CONFIG.INI CREATION AND WARNING ---
if not os.path.exists('config.ini'):
    print("config.ini not found.  Creating a new one...")
    key = Fernet.generate_key().decode()
    config['database'] = {'path': 'users.db'}
    config['encryption'] = {'key': key}
    with open('config.ini', 'w') as configfile:
        config.write(configfile)
    print("config.ini created.  PLEASE READ THIS CAREFULLY:")
    print("  1. Store this file SECURELY, outside your web server's document root.")
    print("  2. Set the permissions to 600 (chmod 600 config.ini).")
    print("  3. **IMPORTANT: The encryption key in this file is for DEVELOPMENT PURPOSES ONLY.**")
    print("     Generate a strong, random key for production and replace the development key.")
    print("     Use `Fernet.generate_key().decode()` to generate a new key.")
# --- END CONFIG.INI CREATION AND WARNING ---

config.read('config.ini')  # Store database path and encryption key in config.ini

DATABASE = config['database']['path']  # Path to the SQLite database
ENCRYPTION_KEY = config['encryption']['key']  # Encryption key for sensitive data

# --- CONFIGURATION FILE SECURITY CHECK ---
def check_config_permissions(config_path):
    """Checks if the config.ini file has secure permissions (600)."""
    try:
        mode = os.stat(config_path).st_mode
        if (mode & 0o777) != 0o600:  # Check if permissions are not 600
            print(f"Error: config.ini has insecure permissions (found: {oct(mode & 0o777)}, expected: 0o600).  Please set permissions to 600 (chmod 600 config.ini).")
            exit()
    except FileNotFoundError:
        print("Error: config.ini not found.")
        exit()

check_config_permissions('config.ini')
# --- END CONFIGURATION FILE SECURITY CHECK ---

# Ensure the encryption key is valid
if not ENCRYPTION_KEY:
    print("Error: Encryption key not found in config.ini.  Generate one using `Fernet.generate_key()` and store it securely.")
    exit()

# Initialize Fernet for encryption/decryption
cipher = Fernet(ENCRYPTION_KEY.encode())


def get_db_connection():
    """Connects to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def create_user_table():
    """Creates the user table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


create_user_table()  # Initialize the table on startup


def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = os.urandom(16).hex()  # Generate a random salt
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password_bytes,
        salt_bytes,
        100000  # Number of iterations - adjust for security/performance
    ).hex()
    return hashed_password, salt


def verify_password(password, stored_hash, salt):
    """Verifies the password against the stored hash and salt."""
    hashed_password, _ = hash_password(password, salt)
    return hashed_password == stored_hash


def encrypt_data(data):
    """Encrypts sensitive data using Fernet."""
    data_bytes = data.encode('utf-8')
    encrypted_data = cipher.encrypt(data_bytes)
    return encrypted_data.decode('utf-8')


def decrypt_data(data):
    """Decrypts sensitive data using Fernet."""
    data_bytes = data.encode('utf-8')
    try:
        decrypted_data = cipher.decrypt(data_bytes).decode('utf-8')
        return decrypted_data
    except cryptography.fernet.InvalidToken:
        print("Error: Invalid token during decryption.  Possible key mismatch or corrupted data.")
        return None  # Or raise an exception, depending on your error handling strategy


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration attempts
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # --- INPUT VALIDATION ---
        if not (username and password):
            return render_template('register.html', error='Username and password are required.')

        if len(username) < 3 or len(username) > 20:
            return render_template('register.html', error='Username must be between 3 and 20 characters.')

        if not username.isalnum():  # Only allow alphanumeric usernames
            return render_template('register.html', error='Username must be alphanumeric.')

        if len(password) < 8:
            return render_template('register.html', error='Password must be at least 8 characters.')

        if not any(char.isupper() for char in password):
            return render_template('register.html', error='Password must contain at least one uppercase letter.')

        if not any(char.islower() for char in password):
            return render_template('register.html', error='Password must contain at least one lowercase letter.')

        if not any(char.isdigit() for char in password):
            return render_template('register.html', error='Password must contain at least one digit.')

        if not any(char in "!@#$%^&*()" for char in password):
            return render_template('register.html', error='Password must contain at least one special character.')

        # Sanitize username
        username = bleach.clean(username)
        # --- END INPUT VALIDATION ---

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Hash the password
            password_hash, salt = hash_password(password)

            # Insert the user into the database
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, password_hash, salt))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))  # Redirect to login after successful registration
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', error='Username already exists.')

    return render_template('register.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit login attempts
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve user from the database
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user['password_hash']
            salt = user['salt']

            if verify_password(password, stored_hash, salt):
                session['username'] = username  # Store username in session
                # session.regenerate() # Regenerate session ID after login - requires Flask-Session
                return redirect(url_for('home'))
            else:
                return render_template('login.html', error='Incorrect password.')
        else:
            return render_template('login.html', error='Incorrect username.')

    return render_template('login.html')


@app.route('/home')
def home():
    """Home page - requires login."""
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")  # Disable debug mode in production, bind to all interfaces

