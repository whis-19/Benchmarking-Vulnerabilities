import os
import hashlib
import secrets
import sqlite3
from flask import Flask, request, render_template, session, redirect, url_for, flash
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = 'users.db'

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
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Security: Rate limiting (very basic example - use a proper library for production)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

def is_rate_limited(username):
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - last_attempt) < LOCKOUT_DURATION:
            return True
    return False

def update_login_attempts(username, success=False):
    import time
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if (now - last_attempt) > LOCKOUT_DURATION:
            login_attempts[username] = (1, now)  # Reset after lockout
        else:
            login_attempts[username] = (attempts + 1, now)
    else:
        login_attempts[username] = (1, now)

    if success:
        if username in login_attempts:
            del login_attempts[username]  # Reset on successful login


# Password hashing function
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Use PBKDF2HMAC for strong password hashing
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password_bytes,
        salt_bytes,
        100000  # Use a high number of iterations
    )
    return salt, hashed_password.hex()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation and sanitization (basic example)
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        # Hash the password
        salt, password_hash = hash_password(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, password_hash, salt))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            flash('Too many login attempts. Please try again later.', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password_hash = user['password_hash']
            salt = user['salt']
            _, hashed_password = hash_password(password, salt)  # Hash the entered password with the stored salt

            if hashed_password == stored_password_hash:
                session['username'] = username
                flash('Login successful!', 'success')
                update_login_attempts(username, success=True)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'error')
                update_login_attempts(username)
        else:
            flash('Invalid username or password.', 'error')
            update_login_attempts(username)

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    return render_template('dashboard.html', username=username)


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    import time
    app.run(debug=True, ssl_context="adhoc") # Enable debug mode for development.  Use a proper WSGI server (e.g., gunicorn) and HTTPS in production.

