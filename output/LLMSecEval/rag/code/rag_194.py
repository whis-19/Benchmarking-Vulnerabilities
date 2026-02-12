import os
import hashlib
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Database Configuration (Move to a separate config file for production)
DATABASE = 'users.db'
CONFIG_FILE = 'config.cfg'  # Store encryption key and other settings

# --- Encryption Key Management ---
def generate_encryption_key():
    """Generates a new Fernet encryption key."""
    key = Fernet.generate_key()
    return key.decode()

def load_encryption_key():
    """Loads the encryption key from the config file.  Generates a new one if it doesn't exist."""
    if not os.path.exists(CONFIG_FILE):
        key = generate_encryption_key()
        with open(CONFIG_FILE, 'w') as f:
            f.write(f"ENCRYPTION_KEY={key}\n")
        return key
    else:
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                if line.startswith("ENCRYPTION_KEY="):
                    return line.split("=", 1)[1].strip()
    return None  # Handle potential errors

encryption_key = load_encryption_key()
fernet = Fernet(encryption_key.encode())


# --- Database Helper Functions ---
def get_db_connection():
    """Connects to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initializes the database with a users table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_login INTEGER DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()

init_db()  # Initialize the database on startup


# --- Password Hashing ---
def hash_password(password):
    """Hashes the password using pbkdf2_hmac."""
    salt = secrets.token_hex(16).encode('utf-8')  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Number of iterations (adjust for security vs. performance)
    )
    return salt.decode() + '$' + hashed_password.hex()  # Store salt and hash

def verify_password(password, stored_hash):
    """Verifies the password against the stored hash."""
    try:
        salt, hash_value = stored_hash.split('$')
        salt = salt.encode('utf-8')
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return hashed_password.hex() == hash_value
    except ValueError:
        return False  # Handle cases where the stored hash is invalid


# --- Encryption/Decryption ---
def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    decrypted_data = fernet.decrypt(encrypted_data.encode()).decode()
    return decrypted_data


# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, first_login FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            user_id = user['id']
            stored_hash = user['password_hash']
            first_login = user['first_login']

            if first_login == 1:
                # Redirect to first login page to set a new password
                session['user_id'] = user_id
                return redirect(url_for('first_login'))

            if verify_password(password, stored_hash):
                session['user_id'] = user_id
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid credentials'

    return render_template('login.html', error=error)


@app.route('/first_login', methods=['GET', 'POST'])
def first_login():
    """Handles the first login, requiring a new password."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return render_template('first_login.html', error="Passwords do not match.")

        if len(new_password) < 8:
            return render_template('first_login.html', error="Password must be at least 8 characters long.")

        hashed_password = hash_password(new_password)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = ?, first_login = 0 WHERE id = ?", (hashed_password, session['user_id']))
        conn.commit()
        conn.close()

        return redirect(url_for('dashboard'))

    return render_template('first_login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = "Passwords do not match."
            return render_template('register.html', error=error)

        if len(password) < 8:
            error = "Password must be at least 8 characters long."
            return render_template('register.html', error=error)

        hashed_password = hash_password(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            error = "Username already exists."

    return render_template('register.html', error=error)


@app.route('/dashboard')
def dashboard():
    """Displays the dashboard."""
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()

        if user:
            username = user['username']
            return render_template('dashboard.html', username=username)
        else:
            return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('user_id', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

