import os
from flask import Flask, render_template, session, redirect, url_for, request, abort, make_response
from functools import wraps
import bcrypt
import secrets
from cryptography.fernet import Fernet
import sqlite3  # Using SQLite for simplicity; consider a more robust database for production
import logging  # For secure logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Security: Generate a strong, random secret key for the Flask app
app.secret_key = secrets.token_hex(32)

# Database setup (using SQLite for simplicity)
DATABASE = 'user_data.db'

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://"  # Use a more persistent storage in production (e.g., Redis)
)


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email_encrypted TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


init_db()

# Encryption Key (Rotate this regularly and store securely - e.g., using a secrets management service)
# NEVER hardcode this in production.  Use environment variables or a secure vault.
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    logging.error("ERROR: ENCRYPTION_KEY environment variable not set.  Application will not start.")
    raise ValueError("ENCRYPTION_KEY environment variable not set.  Application cannot start securely.")  # Fail fast
fernet = Fernet(ENCRYPTION_KEY.encode())


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Hashing function
def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')


def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


def encrypt_data(data):
    """Encrypts data using Fernet."""
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data.decode()


def decrypt_data(encrypted_data):
    """Decrypts data using Fernet."""
    decrypted_data = fernet.decrypt(encrypted_data.encode())
    return decrypted_data.decode()


# WTForms Example
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/minute")  # Rate limit registration attempts
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data

        # Hash the password
        password_hash = hash_password(password)

        # Encrypt sensitive data
        email_encrypted = encrypt_data(email)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password_hash, email_encrypted) VALUES (?, ?, ?)",
                (username, password_hash, email_encrypted)
            )
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', form=form, error='Username already exists.')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and verify_password(password, user['password_hash']):
            session['username'] = user['username']
            return redirect(url_for('info'))
        else:
            return render_template('login.html', error='Invalid credentials.')

    return render_template('login.html')


@app.route('/info')
@login_required
def info():
    username = session['username']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT email_encrypted FROM users WHERE username = ?", (username,))
    user_data = cursor.fetchone()
    conn.close()

    if user_data:
        email = decrypt_data(user_data['email_encrypted'])

        return render_template('info.html', username=username, email=email)
    else:
        # Handle the case where user data is not found (shouldn't happen if login is successful)
        return "User data not found.", 404


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"  # Example CSP
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # Enforce HTTPS
    return response


if __name__ == '__main__':
    app.run(debug=True)

