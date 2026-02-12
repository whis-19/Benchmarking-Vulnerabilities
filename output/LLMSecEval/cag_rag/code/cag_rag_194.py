import os
import secrets
import hashlib
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key
app.secret_key = secrets.token_hex(32)

# Database Configuration
DATABASE = 'users.db'

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Adjust limits as needed
)

# Initialize Database (if it doesn't exist)
def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db():
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

# Create the database and table if they don't exist
with app.app_context():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    db.commit()


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user:
            # Verify password using Werkzeug's secure password hashing
            if check_password_hash(user['password_hash'], password):
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect password.', 'error')
        else:
            flash('Incorrect username.', 'error')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation (example - add more as needed)
        if not (3 <= len(username) <= 20):
            flash("Username must be between 3 and 20 characters.", "error")
            return render_template('register.html')
        if not (8 <= len(password) <= 100):
            flash("Password must be between 8 and 100 characters.", "error")
            return render_template('register.html')

        db = get_db()
        cursor = db.cursor()

        # Hash the password using Werkzeug's secure password hashing
        password_hash = generate_password_hash(password)

        try:
            # Use parameterized query to prevent SQL injection
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    return render_template('dashboard.html', username=username)


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Create the database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)

