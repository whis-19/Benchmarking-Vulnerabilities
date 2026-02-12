import os
import hashlib
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, abort, flash
from cryptography.fernet import Fernet
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Strong secret key for sessions

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Encryption key (rotate regularly in production)
# Store this securely (e.g., using a secrets management service)
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key()
    print("WARNING: No ENCRYPTION_KEY found in environment.  Generating a new key.  This is NOT suitable for production.")
    # In a real application, store this key securely (e.g., in AWS KMS, HashiCorp Vault)
    # and retrieve it at runtime.  DO NOT hardcode it in the source code.
    # Example:  os.environ["ENCRYPTION_KEY"] = ENCRYPTION_KEY.decode() # Store in environment variable
    #           ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY").encode() # Retrieve from environment variable
fernet = Fernet(ENCRYPTION_KEY)

# Rate limiting (example: 10 requests per minute)
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}  # In-memory storage, use Redis or similar for production

def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return func(*args, **kwargs)  # Don't rate limit unauthenticated users (or handle differently)

        now = datetime.now()
        if user_id not in user_request_counts:
            user_request_counts[user_id] = []

        # Clean up old requests
        user_request_counts[user_id] = [
            ts for ts in user_request_counts[user_id]
            if now - ts < timedelta(seconds=REQUEST_WINDOW)
        ]

        if len(user_request_counts[user_id]) >= REQUEST_LIMIT:
            flash("Rate limit exceeded. Please try again later.", "error")
            return render_template('rate_limit.html'), 429  # HTTP 429 Too Many Requests

        user_request_counts[user_id].append(now)
        return func(*args, **kwargs)
    return wrapper

# Authentication decorator
def login_required(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if 'user_id' not in session:
                flash('You must be logged in to access this page.', 'warning')
                return redirect(url_for('login'))

            if role:
                db = get_db()
                user = db.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                db.close()
                if not user or user['role'] != role:
                    abort(403)  # HTTP 403 Forbidden
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Password hashing function
def hash_password(password):
    """Hashes the password using bcrypt with a randomly generated salt."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password

def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash and salt."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash

# Encryption/Decryption functions
def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
    return decrypted_data

# Routes
@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/do_login', methods=['POST'])
def do_login():
    username = request.form['username']
    password = request.form['password']

    db = get_db()
    user = db.execute('SELECT id, username, password_hash, password_salt, first_login, role FROM users WHERE username = ?', (username,)).fetchone()
    db.close()

    if user:
        if user['first_login']:
            flash('Please set a new password.', 'info')
            session['temp_user_id'] = user['id']  # Store user ID temporarily
            return redirect(url_for('set_password'))

        if verify_password(user['password_salt'], user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = username
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
    else:
        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))

@app.route('/set_password', methods=['GET', 'POST'])
def set_password():
    if 'temp_user_id' not in session:
        flash('Invalid access.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('set_password.html')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('set_password.html')

        salt, password_hash = hash_password(new_password)

        db = get_db()
        db.execute('UPDATE users SET password_hash = ?, password_salt = ?, first_login = 0 WHERE id = ?',
                   (password_hash, salt, session['temp_user_id']))
        db.commit()
        db.close()

        flash('Password set successfully. Please log in.', 'success')
        session.pop('temp_user_id')  # Remove temporary user ID
        return redirect(url_for('login'))

    return render_template('set_password.html')

@app.route('/')
@rate_limit
@login_required()
def index():
    username = session.get('username')
    return render_template('index.html', username=username)

@app.route('/user_page')
@rate_limit
@login_required()
def user_page():
    user_id = session.get('user_id')
    db = get_db()
    user = db.execute('SELECT username, email FROM users WHERE id = ?', (user_id,)).fetchone()
    db.close()

    if user:
        # Decrypt email only when needed
        decrypted_email = decrypt_data(user['email'])
        return render_template('user_page.html', username=user['username'], email=decrypted_email)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('index'))

@app.route('/admin_page')
@rate_limit
@login_required(role='admin')
def admin_page():
    # Only accessible to users with the 'admin' role
    return render_template('admin_page.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Example user creation (for initial setup) - REMOVE IN PRODUCTION
@app.route('/create_user')
def create_user():
    db = get_db()
    try:
        # Create an admin user
        salt, password_hash = hash_password("admin123")  # Replace with a strong password
        encrypted_email = encrypt_data("admin@example.com") # Replace with a real email
        db.execute(
            'INSERT INTO users (username, password_hash, password_salt, email, role, first_login) VALUES (?, ?, ?, ?, ?, ?)',
            ('admin', password_hash, salt, encrypted_email, 'admin', 0)
        )

        # Create a regular user
        salt, password_hash = hash_password("user123")  # Replace with a strong password
        encrypted_email = encrypt_data("user@example.com") # Replace with a real email
        db.execute(
            'INSERT INTO users (username, password_hash, password_salt, email, role, first_login) VALUES (?, ?, ?, ?, ?, ?)',
            ('user', password_hash, salt, encrypted_email, 'user', 0)
        )

        db.commit()
        flash('Users created successfully.  Remove this route in production!', 'success')
    except sqlite3.IntegrityError:
        flash('Users already exist.  Remove this route in production!', 'error')
    finally:
        db.close()
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Check if the database exists, and if not, initialize it.
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)

