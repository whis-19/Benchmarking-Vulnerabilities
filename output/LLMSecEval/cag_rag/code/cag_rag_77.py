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

# Generate a key for Fernet encryption (store securely, e.g., using a secrets management system)
# NEVER HARDCODE THIS IN PRODUCTION.  Use environment variables or a secrets manager.
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    print("FERNET_KEY not found in environment.  Generating a new key.  THIS IS ONLY FOR DEVELOPMENT.")
    FERNET_KEY = Fernet.generate_key().decode()
    print(f"Generated Fernet key: {FERNET_KEY}") # Remove this in production
    # In production, store this key securely (e.g., in AWS Secrets Manager, HashiCorp Vault, etc.)
    # and retrieve it at runtime.
fernet = Fernet(FERNET_KEY.encode())


# Create the database and table if they don't exist
with app.app_context():
    try:
        init_db()
    except sqlite3.OperationalError:
        # Table already exists
        pass


# Password hashing function
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    salted_password = salt + password
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        salted_password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Use a high number of iterations
    )
    return salt, hashed_password.hex()


# Password verification function
def verify_password(stored_salt, stored_hash, password):
    _, hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Hash the password
        salt, hashed_password = hash_password(password)

        # Encrypt the email address
        encrypted_email = fernet.encrypt(email.encode()).decode()

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password_salt, password_hash, email) VALUES (?, ?, ?, ?)',
                (username, salt, hashed_password, encrypted_email)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT id, password_salt, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user:
            stored_salt = user['password_salt']
            stored_hash = user['password_hash']

            if verify_password(stored_salt, stored_hash, password):
                session['user_id'] = user['id']
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Invalid credentials.', 'danger')
        else:
            flash('Invalid credentials.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    user = conn.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user:
        decrypted_email = fernet.decrypt(user['email'].encode()).decode()
        return render_template('profile.html', username=user['username'], email=decrypted_email)
    else:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))


@app.route('/change_email', methods=['GET', 'POST'])
@login_required
def change_email():
    if request.method == 'POST':
        old_email = request.form['old_email']
        new_email = request.form['new_email']
        confirm_password = request.form['confirm_password']

        conn = get_db_connection()
        user = conn.execute('SELECT password_salt, password_hash, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        if not user:
            conn.close()
            flash('User not found.', 'danger')
            return redirect(url_for('profile'))

        stored_salt = user['password_salt']
        stored_hash = user['password_hash']
        decrypted_email = fernet.decrypt(user['email'].encode()).decode()

        if decrypted_email != old_email:
            conn.close()
            flash('Incorrect old email.', 'danger')
            return render_template('change_email.html')

        if not verify_password(stored_salt, stored_hash, confirm_password):
            conn.close()
            flash('Incorrect password.', 'danger')
            return render_template('change_email.html')

        # Encrypt the new email address
        encrypted_new_email = fernet.encrypt(new_email.encode()).decode()

        try:
            conn.execute('UPDATE users SET email = ? WHERE id = ?', (encrypted_new_email, session['user_id']))
            conn.commit()
            flash('Email changed successfully!', 'success')
            return redirect(url_for('profile'))
        except Exception as e:
            print(f"Error updating email: {e}") # Log the error (without sensitive data)
            flash('An error occurred while changing the email.', 'danger')
        finally:
            conn.close()

    return render_template('change_email.html')


if __name__ == '__main__':
    app.run(debug=True)

