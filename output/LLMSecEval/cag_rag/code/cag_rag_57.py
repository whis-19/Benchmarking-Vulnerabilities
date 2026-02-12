import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

# Database Configuration
DATABASE = 'users.db'

# Rate Limiting Configuration
LOGIN_ATTEMPTS_WINDOW = timedelta(minutes=5)
MAX_LOGIN_ATTEMPTS = 5

# --- Database Helper Functions ---
def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def close_db(db):
    if db:
        db.close()

def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    close_db(db)

# Create the database if it doesn't exist
if not os.path.exists(DATABASE):
    init_db()

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rate Limiting ---
login_attempts = {}  # Store login attempts per IP address

def is_rate_limited(ip_address):
    now = datetime.now()
    if ip_address in login_attempts:
        attempts, last_attempt = login_attempts[ip_address]
        time_since_last_attempt = now - last_attempt
        if time_since_last_attempt <= LOGIN_ATTEMPTS_WINDOW and attempts >= MAX_LOGIN_ATTEMPTS:
            return True
        elif time_since_last_attempt > LOGIN_ATTEMPTS_WINDOW:
            login_attempts[ip_address] = (1, now)  # Reset attempts
        else:
            login_attempts[ip_address] = (attempts + 1, now)
    else:
        login_attempts[ip_address] = (1, now)
    return False

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')

        try:
            db = get_db()
            # Check if username already exists
            cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone() is not None:
                flash('Username already exists.', 'danger')
                close_db(db)
                return render_template('register.html')

            # Hash the password
            hashed_password = generate_password_hash(password)

            # Insert the user into the database
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            close_db(db)

            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'danger')
            close_db(db)
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr  # Get the user's IP address

        # Rate limiting check
        if is_rate_limited(ip_address):
            flash('Too many login attempts. Please try again later.', 'danger')
            return render_template('login.html')

        try:
            db = get_db()
            cur = db.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            user = cur.fetchone()
            close_db(db)

            if user:
                if check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    flash('Login successful!', 'success')
                    # Reset login attempts on successful login
                    if ip_address in login_attempts:
                        del login_attempts[ip_address]
                    return redirect(url_for('dashboard'))
                else:
                    flash('Incorrect password.', 'danger')
            else:
                flash('Incorrect username.', 'danger')

        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'danger')

        # Update login attempts on failed login
        if ip_address in login_attempts:
            attempts, last_attempt = login_attempts[ip_address]
            login_attempts[ip_address] = (attempts + 1, datetime.now())
        else:
            login_attempts[ip_address] = (1, datetime.now())

        return render_template('login.html')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def index():
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)

