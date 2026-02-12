import os
from flask import Flask, session, render_template, request, redirect, url_for, abort
from functools import wraps
import hashlib
import secrets
import json  # For reading configuration
from cryptography.fernet import Fernet  # For encryption
from datetime import timedelta

app = Flask(__name__)

# --- Configuration Loading and Security ---

# Load configuration from a separate file (e.g., config.json)
CONFIG_FILE = "config.json"  # Store this file outside the web root!
try:
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
        app.config['SECRET_KEY'] = config.get('secret_key')  # Crucial for session security
        if not app.config['SECRET_KEY']:
            raise ValueError("Secret key not found in config.json")

        # Database credentials (example)
        app.config['DB_HOST'] = config.get('db_host')
        app.config['DB_USER'] = config.get('db_user')
        app.config['DB_PASSWORD'] = config.get('db_password')
        app.config['DB_NAME'] = config.get('db_name')

        # Encryption key (Fernet)
        encryption_key = config.get('encryption_key')
        if not encryption_key:
            raise ValueError("Encryption key not found in config.json")
        app.config['ENCRYPTION_KEY'] = encryption_key.encode()  # Convert to bytes

        # User credentials (example)
        app.config['USERS'] = config.get('users', {})  # Dictionary of usernames: hashed passwords

except FileNotFoundError:
    print(f"Error: Configuration file '{CONFIG_FILE}' not found.")
    exit(1)  # Exit if configuration is missing
except json.JSONDecodeError:
    print(f"Error: Invalid JSON format in '{CONFIG_FILE}'.")
    exit(1)
except ValueError as e:
    print(f"Error: {e}")
    exit(1)

# Ensure the secret key is strong
if len(app.config['SECRET_KEY']) < 32:  # Minimum 32 bytes for good security
    print("Warning: Secret key is weak.  Consider generating a stronger one.")

# Initialize Fernet for encryption/decryption
fernet = Fernet(app.config['ENCRYPTION_KEY'])

# Session configuration (important for security)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent client-side script access
app.config['SESSION_COOKIE_SECURE'] = True  # Only send over HTTPS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# --- Authentication Decorator ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Hashing Function ---

def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt + ':' + hashed_password  # Store salt:hash

def check_password(password, stored_hash):
    """Checks if the password matches the stored hash."""
    try:
        salt, hash_value = stored_hash.split(':')
        salted_password = salt + password
        hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
        return hashed_password == hash_value
    except ValueError:
        return False  # Invalid hash format

# --- Encryption/Decryption Functions ---

def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode('utf-8'))
    return encrypted_data.decode('utf-8')

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    try:
        decrypted_data = fernet.decrypt(encrypted_data.encode('utf-8'))
        return decrypted_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")  # Log the error (without sensitive data!)
        return None  # Handle decryption failures gracefully

# --- Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in app.config['USERS']:
            stored_hash = app.config['USERS'][username]
            if check_password(password, stored_hash):
                session['username'] = username
                next_page = request.args.get('next')
                return redirect(next_page or url_for('info'))
            else:
                return render_template('login.html', error='Invalid credentials')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/info')
@login_required
def info():
    # Retrieve encrypted data from session
    encrypted_email = session.get('email')
    encrypted_ssn = session.get('ssn')

    # Decrypt data only when needed for display
    email = decrypt_data(encrypted_email) if encrypted_email else "Email not available"
    ssn_last_4 = decrypt_data(encrypted_ssn)[-4:] if encrypted_ssn else "SSN not available"

    return render_template('info.html', username=session['username'], email=email, ssn_last_4=ssn_last_4)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        ssn = request.form['ssn']

        if username in app.config['USERS']:
            return render_template('register.html', error='Username already exists')

        # Hash the password
        hashed_password = hash_password(password)

        # Encrypt sensitive data
        encrypted_email = encrypt_data(email)
        encrypted_ssn = encrypt_data(ssn)

        # Store the user in the configuration (INSECURE for production - use a database!)
        app.config['USERS'][username] = hashed_password

        # Update the config.json file (VERY CAREFULLY - consider a database!)
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            config = {}
        config['users'] = app.config['USERS']
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)  # Indent for readability

        # Store encrypted data in session (for demonstration - consider a database)
        session['username'] = username
        session['email'] = encrypted_email
        session['ssn'] = encrypted_ssn

        return redirect(url_for('info'))

    return render_template('register.html')

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    # Log the error (without sensitive data!)
    print(f"Internal Server Error: {error}")
    return render_template('500.html'), 500

# --- Main ---

if __name__ == '__main__':
    # Generate a new encryption key if one doesn't exist
    if not os.path.exists(CONFIG_FILE):
        print("Generating initial config.json...")
        new_secret_key = secrets.token_hex(32)
        new_encryption_key = Fernet.generate_key().decode()
        initial_config = {
            "secret_key": new_secret_key,
            "encryption_key": new_encryption_key,
            "users": {}  # Start with no users
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(initial_config, f, indent=4)
        print(f"Generated config.json.  **IMPORTANT:** Store this file securely outside the web root.")

    app.run(debug=True, ssl_context='adhoc') # Use 'adhoc' for development only.  Use proper certificates in production!

