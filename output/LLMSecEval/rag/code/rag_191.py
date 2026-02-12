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
CONFIG_FILE = 'config.ini'  # Example config file

# Encryption Key (Generate and store securely - e.g., using a key management system)
# DO NOT HARDCODE THIS IN PRODUCTION.  Use a KMS or environment variable.
# This is just for demonstration purposes.
def load_encryption_key():
    """Loads the encryption key from a file or generates a new one if it doesn't exist."""
    key_file = 'encryption.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

encryption_key = load_encryption_key()
cipher = Fernet(encryption_key)


# Database Initialization (Run this once to create the table)
def init_db():
    """Initializes the database with a users table."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                first_login INTEGER DEFAULT 1  -- 1 for first login, 0 otherwise
            )
        ''')
        conn.commit()

def get_db_connection():
    """Connects to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

# Password Hashing
def hash_password(password, salt=None):
    """Hashes the password using PBKDF2-HMAC with a random salt."""
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = password.encode('utf-8') + salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        salted_password,
        salt.encode('utf-8'),
        100000  # Recommended number of iterations
    )
    return hashed_password.hex(), salt

def verify_password(password, password_hash, salt):
    """Verifies the password against the stored hash and salt."""
    new_hash, _ = hash_password(password, salt)
    return new_hash == password_hash

# Encryption/Decryption
def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return encrypted_data.decode('utf-8')

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')
    return decrypted_data

# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, username, password_hash, salt, first_login FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user:
                user_id = user['id']
                stored_hash = user['password_hash']
                salt = user['salt']
                first_login = user['first_login']

                if verify_password(password, stored_hash, salt):
                    session['user_id'] = user_id
                    session['username'] = username  # Store username in session

                    if first_login == 1:
                        return redirect(url_for('change_password'))
                    else:
                        return redirect(url_for('home'))
                else:
                    return render_template('login.html', error='Invalid credentials')
            else:
                return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error='Username and password are required.')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                password_hash, salt = hash_password(password)
                cursor.execute('INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
                               (username, password_hash, salt))
                conn.commit()
                return redirect(url_for('login'))  # Redirect to login after successful registration
        except sqlite3.IntegrityError:
            return render_template('register.html', error='Username already exists.')

    return render_template('register.html')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    """Handles first-time password change."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        if not new_password:
            return render_template('change_password.html', error='New password is required.')

        user_id = session['user_id']

        with get_db_connection() as conn:
            cursor = conn.cursor()
            password_hash, salt = hash_password(new_password)
            cursor.execute('UPDATE users SET password_hash = ?, salt = ?, first_login = 0 WHERE id = ?',
                           (password_hash, salt, user_id))
            conn.commit()

        return redirect(url_for('home'))

    return render_template('change_password.html')


@app.route('/home')
def home():
    """Home page - requires login."""
    if 'user_id' in session:
        username = session['username']
        return render_template('home.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Initialize the database on startup
    app.run(debug=True)

