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
# NEVER hardcode the key.  Generate it once and store it securely.
# Example:
# if not os.path.exists("encryption.key"):
#     key = Fernet.generate_key()
#     with open("encryption.key", "wb") as key_file:
#         key_file.write(key)
try:
    with open("encryption.key", "rb") as key_file:
        ENCRYPTION_KEY = key_file.read()
except FileNotFoundError:
    print("Error: encryption.key not found.  Please generate and store a key securely.")
    exit()  # Or handle the error more gracefully

fernet = Fernet(ENCRYPTION_KEY)


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email_encrypted BLOB NOT NULL,
            first_login INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()


create_tables()  # Ensure tables exist on startup


def hash_password(password):
    """Hashes the password using SHA-256."""
    salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return salt, hashed_password


def verify_password(stored_salt, stored_hash, password):
    """Verifies the password against the stored hash."""
    salted_password = stored_salt + password
    hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
    return hashed_password == stored_hash


def encrypt_data(data):
    """Encrypts data using Fernet."""
    return fernet.encrypt(data.encode('utf-8'))


def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    return fernet.decrypt(encrypted_data).decode('utf-8')


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
        cursor = conn.cursor()

        try:
            salt, password_hash = hash_password(password)
            email_encrypted = encrypt_data(email)

            cursor.execute("INSERT INTO users (username, password_hash, email_encrypted, first_login) VALUES (?, ?, ?, 1)",
                           (username, salt + ":" + password_hash, email_encrypted))  # Store salt:hash
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, username, password_hash, email_encrypted, first_login FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_salt, stored_hash = user['password_hash'].split(":")
            if verify_password(stored_salt, stored_hash, password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['email_encrypted'] = user['email_encrypted']
                session['first_login'] = user['first_login']

                if user['first_login'] == 1:
                    return redirect(url_for('change_password_first_login'))
                else:
                    return redirect(url_for('index'))
            else:
                flash('Invalid credentials.', 'error')
        else:
            flash('Invalid credentials.', 'error')

    return render_template('login.html')


@app.route('/change_password_first_login', methods=['GET', 'POST'])
def change_password_first_login():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return render_template('change_password_first_login.html')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('change_password_first_login.html')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('change_password_first_login.html')

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            salt, password_hash = hash_password(new_password)
            cursor.execute("UPDATE users SET password_hash = ?, first_login = 0 WHERE id = ?", (salt + ":" + password_hash, session['user_id']))
            conn.commit()
            session['first_login'] = 0
            flash('Password changed successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            logging.error(f"Error changing password: {e}")  # Log the error
            flash('An error occurred while changing the password.', 'error')
        finally:
            conn.close()

    return render_template('change_password_first_login.html')


@app.route('/')
def index():
    if 'user_id' in session:
        email = decrypt_data(session['email_encrypted'])
        return render_template('index.html', username=session['username'], email=email)
    return redirect(url_for('login'))


@app.route('/change_email', methods=['GET', 'POST'])
def change_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        confirm_password = request.form['confirm_password']

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
            return render_template('change_email.html')

        stored_salt, stored_hash = user['password_hash'].split(":")
        if not verify_password(stored_salt, stored_hash, confirm_password):
            flash('Incorrect password.', 'error')
            conn.close()
            return render_template('change_email.html')

        decrypted_old_email = decrypt_data(user['email_encrypted'])
        if decrypted_old_email != old_email:
            flash('Incorrect old email.', 'error')
            conn.close()
            return render_template('change_email.html')

        try:
            new_email_encrypted = encrypt_data(new_email)
            cursor.execute("UPDATE users SET email_encrypted = ? WHERE id = ?", (new_email_encrypted, session['user_id']))
            conn.commit()
            session['email_encrypted'] = new_email_encrypted  # Update session
            flash('Email changed successfully!', 'success')
            logging.info(f"User {session['username']} changed email.") # Log email change (without sensitive data)
        except Exception as e:
            logging.error(f"Error changing email: {e}")
            flash('An error occurred while changing the email.', 'error')
        finally:
            conn.close()

    return render_template('change_email.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('email_encrypted', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Use adhoc for development only.  Use proper certificates in production.

