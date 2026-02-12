import os
import hashlib
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
import logging

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

# Configure logging (important for security audits, but avoid logging sensitive data)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database Configuration (Store in a separate, secure location)
DATABASE_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'users.db')  # Outside web root
# Ensure the directory exists
os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)

# Encryption Key (Store securely, e.g., using a key management system)
# DO NOT HARDCODE.  Retrieve from environment variable or secure storage.
ENCRYPTION_KEY = os.environ.get("EMAIL_CHANGE_ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    logging.error("Encryption key not found in environment.  Exiting.")
    raise ValueError("Encryption key not found.  Application cannot start.")

fernet = Fernet(ENCRYPTION_KEY.encode())  # Initialize Fernet with the key

# --- Database Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def create_user_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email_encrypted BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()

create_user_table()  # Initialize the database table

# --- Encryption/Decryption Functions ---
def encrypt_data(data):
    """Encrypts data using Fernet."""
    return fernet.encrypt(data.encode())

def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    return fernet.decrypt(encrypted_data).decode()

# --- Password Hashing ---
def hash_password(password):
    """Hashes a password using SHA-256 with a salt."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
    return salt, hashed_password

def verify_password(password, salt, hashed_password):
    """Verifies a password against a stored hash and salt."""
    salted_password = salt + password
    new_hash = hashlib.sha256(salted_password.encode()).hexdigest()
    return new_hash == hashed_password

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Validate input (add more robust validation)
        if not username or not password or not email:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            salt, password_hash = hash_password(password)
            email_encrypted = encrypt_data(email)

            cursor.execute("INSERT INTO users (username, password_hash, email_encrypted) VALUES (?, ?, ?)",
                           (username, password_hash + ":" + salt, email_encrypted)) # Store salt with hash
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, password_hash, email_encrypted FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            password_hash_with_salt = user['password_hash']
            password_hash, salt = password_hash_with_salt.split(":")
            if verify_password(password, salt, password_hash):
                session['user_id'] = user['id']
                session['username'] = username
                logging.info(f"User {username} logged in successfully.")
                return redirect(url_for('profile'))
            else:
                flash('Invalid credentials.', 'error')
                logging.warning(f"Failed login attempt for user {username}.")
        else:
            flash('Invalid credentials.', 'error')
            logging.warning(f"Failed login attempt for user {username}.")

    return render_template('login.html')


@app.route('/profile')
def profile():
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT email_encrypted FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()

        if user:
            try:
                email = decrypt_data(user['email_encrypted'])
                return render_template('profile.html', username=session['username'], email=email)
            except Exception as e:
                logging.error(f"Error decrypting email for user {session['username']}: {e}")
                flash("Error displaying profile information.", "error")
                return redirect(url_for('logout')) # Log out if profile can't be displayed.
        else:
            flash("User not found.", "error")
            return redirect(url_for('logout'))
    else:
        return redirect(url_for('login'))


@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        confirm_password = request.form['confirm_password']

        # Input validation (add more robust validation)
        if not old_email or not new_email or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_email.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash, email_encrypted FROM users WHERE id = ?", (session['user_id'],))
        user = cursor.fetchone()

        if not user:
            flash('User not found.', 'error')
            conn.close()
            return redirect(url_for('profile'))

        try:
            decrypted_email = decrypt_data(user['email_encrypted'])
        except Exception as e:
            logging.error(f"Error decrypting email during change_email for user {session['username']}: {e}")
            flash("Error processing request. Please try again.", "error")
            conn.close()
            return redirect(url_for('profile'))

        if decrypted_email != old_email:
            flash('Incorrect old email.', 'error')
            conn.close()
            return render_template('change_email.html')

        password_hash_with_salt = user['password_hash']
        password_hash, salt = password_hash_with_salt.split(":")

        if not verify_password(confirm_password, salt, password_hash):
            flash('Incorrect password.', 'error')
            conn.close()
            return render_template('change_email.html')

        try:
            new_email_encrypted = encrypt_data(new_email)
            cursor.execute("UPDATE users SET email_encrypted = ? WHERE id = ?", (new_email_encrypted, session['user_id']))
            conn.commit()
            flash('Email changed successfully!', 'success')
            logging.info(f"User {session['username']} changed email successfully.")
        except Exception as e:
            logging.error(f"Error updating email for user {session['username']}: {e}")
            flash('Error changing email. Please try again.', 'error')
            conn.rollback()
        finally:
            conn.close()

        return redirect(url_for('profile'))

    return render_template('change_email.html')


@app.route('/logout')
def logout():
    logging.info(f"User {session.get('username', 'Unknown')} logged out.")
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    # NEVER USE debug=True IN PRODUCTION!
    app.run(debug=False, host='0.0.0.0', port=5000)

