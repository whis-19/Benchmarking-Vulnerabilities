import os
import secrets
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate a strong, random secret key

DATABASE = 'users.db'

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        ''')
        db.commit()

init_db()

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def close_db_connection(conn):
    conn.close()

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # --- Input Validation ---
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 50:
            flash('Username must be between 3 and 50 characters.', 'danger')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')

        # --- Generate Salt and Hash Password ---
        salt = secrets.token_hex(16)  # Generate a random salt
        password_hash = generate_password_hash(password + salt) # Hash the password with the salt

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # --- Parameterized Query ---
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, password_hash, salt))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
        finally:
            close_db_connection(conn)

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # --- Parameterized Query ---
        cursor.execute("SELECT id, username, password_hash, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        close_db_connection(conn)

        if user:
            stored_password_hash = user['password_hash']
            salt = user['salt']

            # --- Verify Password ---
            if generate_password_hash(password + salt) == stored_password_hash:
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['username'])


@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)

