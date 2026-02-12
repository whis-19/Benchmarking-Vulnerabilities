import os
import hashlib
import secrets
import sqlite3
from flask import Flask, render_template, request, session, redirect, url_for, flash
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()
        db.close()

# Create the database and table if they don't exist
try:
    init_db()
except sqlite3.OperationalError:
    # Table already exists
    pass


# Password hashing function (using PBKDF2)
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)  # Generate a random salt
    
    # Use PBKDF2 for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',  # Use SHA256
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations (adjust as needed)
    ).hex()
    return salt, hashed_password


# Function to verify password
def verify_password(stored_salt, stored_hash, password):
    # Hash the provided password with the stored salt
    _, hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash


# Rate limiting (simple implementation, consider using a library like Flask-Limiter)
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
        login_attempts.pop(username, None)  # Remove on successful login


# Authentication decorator
def login_required():
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if 'username' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            return fn(*args, **kwargs)
        return decorated_view
    return login_required  # Corrected: Return the decorator


# Routes
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            flash('Too many login attempts. Please try again later.', 'danger')
            return render_template('login.html')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        db.close()

        if user:
            stored_salt = user['salt']
            stored_hash = user['password']

            if verify_password(stored_salt, stored_hash, password):
                update_login_attempts(username, success=True)
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('session_page'))
            else:
                update_login_attempts(username)
                flash('Incorrect username or password.', 'danger')
        else:
            update_login_attempts(username)
            flash('Incorrect username or password.', 'danger')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        db = get_db()
        existing_user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if existing_user:
            db.close()
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        salt, hashed_password = hash_password(password)

        try:
            db.execute('INSERT INTO users (username, password, salt) VALUES (?, ?, ?)',
                       (username, hashed_password, salt))
            db.commit()
            db.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.close()
            flash(f'Registration failed: {str(e)}', 'danger')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/session')
@login_required()
def session_page():
    username = session['username']
    return render_template('session.html', username=username)


@app.route('/logout')
@login_required()
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    import time
    app.run(debug=True)

