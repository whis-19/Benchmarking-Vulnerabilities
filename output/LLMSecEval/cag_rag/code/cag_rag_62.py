import os
import hashlib
import secrets
from flask import Flask, render_template, request, session, redirect, url_for, abort
from functools import wraps
import time
import sqlite3

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Database setup (using SQLite for simplicity - consider a more robust solution for production)
DATABASE = 'users.db'

def get_db():
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        # Enable foreign key support (important for relational integrity)
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database if it doesn't exist
if not os.path.exists(DATABASE):
    init_db()


# Password hashing function (using PBKDF2)
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Use PBKDF2 for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations (adjust as needed - higher is better)
    )
    return salt, hashed_password.hex()


# Verify password function
def verify_password(stored_salt, stored_hash, password):
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        stored_salt.encode('utf-8'),
        100000
    )
    return hashed_password.hex() == stored_hash


# Rate limiting (simple implementation - consider a more robust solution)
login_attempts = {}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

def is_rate_limited(username):
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if attempts >= MAX_LOGIN_ATTEMPTS and (now - last_attempt) < LOCKOUT_DURATION:
            return True
    return False

def update_login_attempts(username, success=False):
    now = time.time()
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        if (now - last_attempt) > LOCKOUT_DURATION:
            login_attempts[username] = (1, now)  # Reset attempts after lockout
        else:
            if success:
                del login_attempts[username] # Reset on successful login
            else:
                login_attempts[username] = (attempts + 1, now)
    else:
        login_attempts[username] = (1, now)


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            error = "Too many login attempts. Please try again later."
            return render_template('login.html', error=error)

        db = get_db()
        cur = db.execute('SELECT salt, password_hash FROM users WHERE username = ?', (username,))
        user = cur.fetchone()

        if user:
            stored_salt, stored_hash = user
            if verify_password(stored_salt, stored_hash, password):
                update_login_attempts(username, success=True)
                session['username'] = username
                return redirect(url_for('session_page'))
            else:
                update_login_attempts(username)
                error = 'Incorrect username or password.'
        else:
            update_login_attempts(username)
            error = 'Incorrect username or password.'

    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            error = 'Please enter both a username and password.'
        else:
            db = get_db()
            cur = db.execute('SELECT username FROM users WHERE username = ?', (username,))
            existing_user = cur.fetchone()

            if existing_user:
                error = 'Username already exists.'
            else:
                salt, password_hash = hash_password(password)
                try:
                    db.execute('INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)',
                               (username, salt, password_hash))
                    db.commit()
                    return redirect(url_for('login'))  # Redirect to login after successful registration
                except sqlite3.Error as e:
                    error = f"Database error: {e}"

    return render_template('register.html', error=error)


@app.route('/session')
@login_required
def session_page():
    username = session['username']
    return render_template('session.html', username=username)


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc') # Enable debug mode and SSL for development

