import os
import hashlib
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, flash
from functools import wraps
import sqlite3  # Consider using a more robust database like PostgreSQL
from cryptography.fernet import Fernet  # For encrypting sensitive data in the database

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    conn.close()

# Encryption key (store securely, e.g., using a secrets management system)
# NEVER HARDCODE THIS IN PRODUCTION.  Use environment variables or a secrets manager.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    print("ERROR: ENCRYPTION_KEY not set in environment.  Generating a new key for development ONLY.")
    ENCRYPTION_KEY = Fernet.generate_key().decode()  # ONLY FOR DEVELOPMENT
    print(f"Generated key (DEVELOPMENT ONLY): {ENCRYPTION_KEY}")
    # In a real application, store this securely (e.g., HashiCorp Vault, AWS KMS)
    # and retrieve it at runtime.
else:
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

cipher = Fernet(ENCRYPTION_KEY)


# --- Security Utilities ---

def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = secrets.token_hex(16).encode('utf-8')  # Generate a random salt
    else:
        salt = salt.encode('utf-8')

    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return salt.decode('utf-8') + ':' + hashed_password.hex()

def verify_password(stored_password, provided_password):
    """Verifies the provided password against the stored hash."""
    try:
        salt, hashed_password = stored_password.split(':')
        calculated_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return secrets.compare_digest(calculated_hash.hex(), hashed_password)
    except ValueError:
        # Handle cases where the stored password format is invalid
        return False

def encrypt_data(data):
    """Encrypts data using Fernet."""
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    return cipher.decrypt(encrypted_data.encode()).decode()


# --- Authentication Decorator ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        if not username or not password or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if username or email already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            flash('Username already exists.', 'error')
            conn.close()
            return render_template('register.html')

        cur.execute("SELECT id FROM users WHERE email = ?", (encrypt_data(email),)) # Encrypt email before checking
        if cur.fetchone() is not None:
            flash('Email already exists.', 'error')
            conn.close()
            return render_template('register.html')

        # Hash the password
        hashed_password = hash_password(password)

        # Encrypt the email before storing it
        encrypted_email = encrypt_data(email)

        # Insert the new user into the database
        cur.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                    (username, hashed_password, encrypted_email))
        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and verify_password(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password.', 'error')
            return render_template('login.html')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT email FROM users WHERE id = ?", (session['user_id'],))
    user = cur.fetchone()
    conn.close()

    if user:
        decrypted_email = decrypt_data(user['email'])
        return render_template('profile.html', username=session['username'], email=decrypted_email)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('logout'))


@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        confirm_password = request.form['confirm_password']

        if not old_email or not new_email or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_email.html')

        conn = get_db_connection()
        cur = conn.cursor()

        # Verify the user's password
        cur.execute("SELECT password, email FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()

        if not user:
            flash('User not found.', 'error')
            conn.close()
            return redirect(url_for('logout'))

        if not verify_password(user['password'], confirm_password):
            flash('Incorrect password.', 'error')
            conn.close()
            return render_template('change_email.html')

        # Verify the old email matches the current email
        decrypted_email = decrypt_data(user['email'])
        if old_email != decrypted_email:
            flash('Incorrect old email.', 'error')
            conn.close()
            return render_template('change_email.html')

        # Check if the new email already exists
        cur.execute("SELECT id FROM users WHERE email = ?", (encrypt_data(new_email),))
        if cur.fetchone() is not None:
            flash('New email already exists.', 'error')
            conn.close()
            return render_template('change_email.html')

        # Update the email in the database
        encrypted_new_email = encrypt_data(new_email)
        cur.execute("UPDATE users SET email = ? WHERE id = ?", (encrypted_new_email, session['user_id']))
        conn.commit()
        conn.close()

        flash('Email changed successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('change_email.html')


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    # Initialize the database (create tables if they don't exist)
    try:
        init_db()
    except Exception as e:
        print(f"Error initializing database: {e}")

    app.run(debug=True)

