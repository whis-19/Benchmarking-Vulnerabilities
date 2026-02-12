import os
import secrets
import bcrypt
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, session, flash
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

DATABASE = 'users.db'

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
        db.commit()

init_db()

# --- Password Hashing ---
def hash_password(password):
    """Hashes the password using bcrypt."""
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')  # Store as string

def verify_password(password, hashed_password):
    """Verifies the password against the stored hash."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))


# --- Input Validation ---
def validate_username(username):
    """Validates the username."""
    if not (3 <= len(username) <= 50):
        return False, "Username must be between 3 and 50 characters."
    if not username.isalnum():  # Only allow alphanumeric characters
        return False, "Username must contain only alphanumeric characters."
    return True, None

def validate_password(password):
    """Validates the password."""
    if not (8 <= len(password) <= 100):
        return False, "Password must be between 8 and 100 characters."
    # Add more complex password requirements here if needed (e.g., special characters, numbers)
    return True, None


# --- Registration Route ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input Validation
        username_valid, username_error = validate_username(username)
        password_valid, password_error = validate_password(password)

        if not username_valid:
            flash(username_error, 'error')
            return render_template('register.html')

        if not password_valid:
            flash(password_error, 'error')
            return render_template('register.html')

        try:
            hashed_password = hash_password(password)

            with sqlite3.connect(DATABASE) as db:
                cursor = db.cursor()
                cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
                db.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username already exists.', 'error')
            return render_template('register.html')

    return render_template('register.html')


# --- Login Route ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect(DATABASE) as db:
            cursor = db.cursor()
            cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

        if user:
            user_id, hashed_password = user
            if verify_password(password, hashed_password):
                session['user_id'] = user_id
                session['username'] = username  # Store username in session
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Incorrect password.', 'error')
        else:
            flash('Username not found.', 'error')

    return render_template('login.html')


# --- Logout Route ---
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# --- Home Route (Example) ---
@app.route('/')
@app.route('/home')
def home():
    if 'user_id' in session:
        username = session['username']
        return render_template('home.html', username=escape(username)) # Escape username for safe rendering
    else:
        return redirect(url_for('login'))


# --- Example Route with CSRF Protection (Illustrative) ---
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # In a real application, you would use a CSRF library like Flask-WTF
    # to generate and validate CSRF tokens.  This is a simplified example.

    csrf_token = secrets.token_hex(16)
    session['csrf_token'] = csrf_token

    if request.method == 'POST':
        if request.form.get('csrf_token') != session.get('csrf_token'):
            flash('CSRF token invalid.', 'error')
            return render_template('profile.html', csrf_token=csrf_token)

        # Process profile update here (with proper validation and sanitization)
        # ...

        flash('Profile updated!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', csrf_token=csrf_token)


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


# --- Template Filters (Example - escaping) ---
@app.template_filter('escape_html')
def escape_html_filter(text):
    return escape(text)


if __name__ == '__main__':
    app.run(debug=True)

