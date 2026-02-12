import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

# Security: Generate a cryptographically secure secret key for the session
app.secret_key = secrets.token_hex(32)

# Database setup (using SQLite for simplicity, consider PostgreSQL for production)
DATABASE = 'users.db'

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
                password TEXT NOT NULL
            )
        ''')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

init_db()

# Security: CSRF protection (simplified example)
def generate_csrf_token():
    return secrets.token_hex(16)

def validate_csrf_token(token):
    return session.get('csrf_token') == token

# Decorator for routes that require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Security: Input validation (basic example)
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('register.html')

        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters.', 'error')
            return render_template('register.html')

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html')

        # Security: Password hashing using werkzeug.security (bcrypt by default)
        hashed_password = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Security: Parameterized query to prevent SQL injection
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            flash('An error occurred during registration.', 'error')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Security: Parameterized query to prevent SQL injection
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            # Security: Password verification using werkzeug.security
            if check_password_hash(user['password'], password):
                session['username'] = username
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Incorrect password.', 'error')
        else:
            flash('Incorrect username.', 'error')

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
    # Security: Generate CSRF token for any state-changing operations on the profile page
    session['csrf_token'] = generate_csrf_token()
    return render_template('profile.html', username=session['username'], csrf_token=session['csrf_token'])

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        csrf_token = request.form['csrf_token']

        # Security: CSRF token validation
        if not validate_csrf_token(csrf_token):
            flash('CSRF token is invalid.', 'error')
            return redirect(url_for('profile'))

        # Security: Input validation for new password
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            return redirect(url_for('profile'))

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (session['username'],))
        user = cursor.fetchone()

        if user:
            if check_password_hash(user['password'], old_password):
                # Security: Hash the new password
                hashed_password = generate_password_hash(new_password)

                # Security: Parameterized query to update password
                cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, session['username']))
                conn.commit()
                conn.close()

                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Incorrect old password.', 'error')
        else:
            flash('User not found.', 'error')

        conn.close()
        return redirect(url_for('profile'))

# Security:  Content Security Policy (CSP) -  Example, adjust to your needs
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    return response

if __name__ == '__main__':
    # Security:  Do NOT use debug mode in production
    app.run(debug=True)

