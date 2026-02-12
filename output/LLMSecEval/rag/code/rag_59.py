import hashlib
import os
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session
from cryptography.fernet import Fernet
import configparser

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Securely generate a random secret key

# Configuration loading
config = configparser.ConfigParser()
config.read('config.ini')  # Store database path and encryption key in config.ini

DATABASE = config['database']['path']  # Path to the SQLite database
ENCRYPTION_KEY = config['encryption']['key']  # Encryption key for sensitive data

# Ensure the encryption key is valid
if not ENCRYPTION_KEY:
    print("Error: Encryption key not found in config.ini.  Generate one and add it.")
    exit()

# Initialize Fernet for encryption/decryption
cipher = Fernet(ENCRYPTION_KEY.encode())


def get_db_connection():
    """Connects to the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def create_user(username, password):
    """Creates a new user in the database, hashing the password."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Hash the password using pbkdf2_hmac
    salt = os.urandom(16)  # Generate a random salt
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Recommended number of iterations
    )

    # Encrypt the hashed password and salt before storing
    encrypted_password = cipher.encrypt(hashed_password).decode()
    encrypted_salt = cipher.encrypt(salt).decode()

    try:
        cursor.execute(
            "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
            (username, encrypted_password, encrypted_salt)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Handle username already exists error
        return False
    finally:
        conn.close()


def verify_password(username, password):
    """Verifies the password against the stored hash."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        encrypted_password = result['password']
        encrypted_salt = result['salt']

        # Decrypt the stored password and salt
        hashed_password = cipher.decrypt(encrypted_password.encode())
        salt = cipher.decrypt(encrypted_salt.encode())

        # Hash the provided password with the stored salt
        new_hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )

        # Compare the generated hash with the stored hash
        return new_hashed_password == hashed_password
    else:
        return False  # Username not found


def check_username_exists(username):
    """Checks if a username already exists in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    return result is not None


def initialize_database():
    """Initializes the database with a users table if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error="Username and password are required.")

        if check_username_exists(username):
            return render_template('register.html', error="Username already exists.")

        if create_user(username, password):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Registration failed.")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if verify_password(username, password):
            session['username'] = username  # Store username in session
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="Invalid username or password.")

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


@app.route('/')
def index():
    """Index page - redirects to login."""
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Initialize the database on startup
    initialize_database()

    # Create a default config.ini if it doesn't exist
    if not os.path.exists('config.ini'):
        print("Creating default config.ini.  Please configure the database path and encryption key.")
        key = Fernet.generate_key().decode()
        default_config = f"""
[database]
path = database.db

[encryption]
key = {key}
"""
        with open('config.ini', 'w') as configfile:
            configfile.write(default_config)

    app.run(debug=True)

