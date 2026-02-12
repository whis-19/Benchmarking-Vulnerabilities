import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key
app.secret_key = secrets.token_hex(32)

# Database Configuration
DATABASE = 'users.db'

# Rate Limiting Configuration
LOGIN_ATTEMPTS_WINDOW = timedelta(minutes=5)
MAX_LOGIN_ATTEMPTS = 5

# --- Database Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                first_login INTEGER DEFAULT 1,
                login_attempts INTEGER DEFAULT 0,
                last_login_attempt DATETIME
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

init_db()  # Initialize the database on application start

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Rate Limiting ---
def is_rate_limited(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT login_attempts, last_login_attempt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return False  # User doesn't exist, so not rate limited

    login_attempts = user['login_attempts']
    last_login_attempt = user['last_login_attempt']

    if last_login_attempt:
        last_attempt_time = datetime.fromisoformat(last_login_attempt)
        time_elapsed = datetime.now() - last_attempt_time
        if time_elapsed <= LOGIN_ATTEMPTS_WINDOW and login_attempts >= MAX_LOGIN_ATTEMPTS:
            return True
    return False

def update_login_attempts(username, success=False):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    if success:
        cursor.execute("UPDATE users SET login_attempts = 0, last_login_attempt = NULL WHERE username = ?", (username,))
    else:
        cursor.execute("""
            UPDATE users
            SET login_attempts = login_attempts + 1,
                last_login_attempt = ?
            WHERE username = ?
        """, (now, username))

    conn.commit()
    conn.close()

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_rate_limited(username):
            flash('Too many failed login attempts. Please try again later.', 'error')
            return render_template('login.html')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, first_login FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            password_hash = user['password_hash']
            if check_password_hash(password_hash, password):
                update_login_attempts(username, success=True)
                session['username'] = username
                session['user_id'] = user['id']

                if user['first_login']:
                    return redirect(url_for('change_password'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                update_login_attempts(username)
                flash('Invalid username or password', 'error')
        else:
            update_login_attempts(username)
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation
        if not (username and password):
            flash('Username and password are required.', 'error')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Hash the password
            password_hash = generate_password_hash(password)

            # Insert the user into the database
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            conn.commit()
            conn.close()

            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash('An error occurred during registration.', 'error')

    return render_template('register.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']

        if not new_password:
            flash('New password is required.', 'error')
            return render_template('change_password.html')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('change_password.html')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            password_hash = generate_password_hash(new_password)

            cursor.execute("UPDATE users SET password_hash = ?, first_login = 0 WHERE username = ?", (password_hash, session['username']))
            conn.commit()
            conn.close()

            flash('Password changed successfully.', 'success')
            return redirect(url_for('dashboard'))

        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash('An error occurred while changing the password.', 'error')

    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

