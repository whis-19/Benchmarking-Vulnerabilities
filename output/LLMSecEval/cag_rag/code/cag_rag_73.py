import os
import hashlib
import secrets
from functools import wraps
from flask import Flask, session, redirect, url_for, request, abort, render_template
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3  # Consider using a more robust database in production

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a strong, random secret key

# Database setup (SQLite for simplicity, consider PostgreSQL/MySQL for production)
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

# Create the database if it doesn't exist (run this once)
if not os.path.exists(DATABASE):
    init_db()


# Password hashing function (using bcrypt via werkzeug)
def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, hashed_password):
    return check_password_hash(hashed_password, password)


# Authentication decorator
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))

            if role:
                db = get_db()
                cur = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
                user = cur.fetchone()
                if user is None or (role == 'admin' and not user[0]):
                    abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Rate limiting (very basic example, consider using a library like Flask-Limiter)
login_attempts = {}  # Store login attempts per IP address
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 60  # seconds

def is_rate_limited(ip_address):
    if ip_address in login_attempts:
        attempts, timestamp = login_attempts[ip_address]
        if attempts >= MAX_LOGIN_ATTEMPTS and (time.time() - timestamp) < LOCKOUT_DURATION:
            return True
    return False

def update_login_attempts(ip_address, success=False):
    import time
    if ip_address in login_attempts:
        attempts, timestamp = login_attempts[ip_address]
        if success:
            del login_attempts[ip_address]  # Reset on successful login
        else:
            login_attempts[ip_address] = (attempts + 1, time.time())
    else:
        login_attempts[ip_address] = (1, time.time())


# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        db = get_db()
        cur = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
        user = cur.fetchone()
        if user and user[0]:
            return redirect(url_for('admin_page'))
        else:
            return redirect(url_for('user_page'))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr  # Get the user's IP address

        if is_rate_limited(ip_address):
            return "Too many login attempts. Please try again later.", 429

        db = get_db()
        cur = db.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and verify_password(password, user[1]):
            session['user_id'] = user[0]
            update_login_attempts(ip_address, success=True)
            db = get_db()
            cur = db.execute("SELECT is_admin FROM users WHERE id = ?", (session['user_id'],))
            user = cur.fetchone()
            if user and user[0]:
                return redirect(url_for('admin_page'))
            else:
                return redirect(url_for('user_page'))
        else:
            update_login_attempts(ip_address)
            return "Invalid credentials", 401

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate username and password (e.g., length, complexity)
        if not (4 <= len(username) <= 20 and 8 <= len(password) <= 100):
            return "Username must be between 4 and 20 characters and password must be between 8 and 100 characters.", 400

        hashed_password = hash_password(password)

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
                       (username, hashed_password, False))  # Default: not admin
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already exists", 409

    return render_template('register.html')


@app.route('/user')
@login_required()
def user_page():
    return "User Page"


@app.route('/admin')
@login_required(role='admin')
def admin_page():
    return "Admin Page"


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))


# Error handling
@app.errorhandler(403)
def forbidden(e):
    return "Forbidden", 403

import time
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

