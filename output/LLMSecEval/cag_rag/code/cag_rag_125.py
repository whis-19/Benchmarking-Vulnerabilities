import sqlite3
import re
from flask import Flask, request, render_template, session, redirect, url_for, flash
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(24)  # Generate a random secret key

DATABASE = 'users.db'

# --- Database Setup ---
def get_db():
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
        # Enable foreign key constraints for data integrity
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
        with open('schema.sql', 'r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database and tables if they don't exist.  Call this once.
# Example:  `python your_app.py && python` then in the python interpreter:
# `from your_app import init_db; init_db()`

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Input Validation ---
def is_valid_email(email):
    """Basic email validation using regex."""
    email_regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_regex, email) is not None

# --- CSRF Token Generation ---
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    if 'csrf_token' not in session or token != session['csrf_token']:
        return False
    return True

# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not is_valid_email(email):
            flash('Invalid email address.', 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

        try:
            db = get_db()
            hashed_password = generate_password_hash(password)

            # Check if the email already exists
            cursor = db.execute("SELECT id FROM users WHERE email = ?", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                flash('Email address already registered.', 'error')
                return render_template('register.html', csrf_token=generate_csrf_token())

            # Create the user with limited privileges.  This example grants read/write to *only* their own data.
            db.execute("INSERT INTO users (email, password, role) VALUES (?, ?, ?)", (email, hashed_password, 'user'))
            db.commit()

            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.Error as e:
            print(f"Database error: {e}")  # Log the error
            flash('An error occurred during registration. Please try again.', 'error')
            return render_template('register.html', csrf_token=generate_csrf_token())

    return render_template('register.html', csrf_token=generate_csrf_token())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not is_valid_email(email):
            flash('Invalid email address.', 'error')
            return render_template('login.html', csrf_token=generate_csrf_token())

        try:
            db = get_db()
            cursor = db.execute("SELECT id, email, password, role FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['email'] = user['email']
                session['role'] = user['role'] # Store the user's role in the session
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))
            else:
                flash('Invalid email or password.', 'error')
                return render_template('login.html', csrf_token=generate_csrf_token())

        except sqlite3.Error as e:
            print(f"Database error: {e}")  # Log the error
            flash('An error occurred during login. Please try again.', 'error')
            return render_template('login.html', csrf_token=generate_csrf_token())

    return render_template('login.html', csrf_token=generate_csrf_token())


@app.route('/profile')
@login_required
def profile():
    email = session['email']
    return render_template('profile.html', email=email)


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('email', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/unsubscribe', methods=['GET', 'POST'])
def unsubscribe():
    if request.method == 'POST':
        email = request.form['email']
        csrf_token = request.form['csrf_token']

        if not validate_csrf_token(csrf_token):
            flash('CSRF token is invalid.', 'error')
            return render_template('unsubscribe.html', csrf_token=generate_csrf_token())

        if not is_valid_email(email):
            flash('Invalid email address.', 'error')
            return render_template('unsubscribe.html', csrf_token=generate_csrf_token())

        try:
            db = get_db()
            cursor = db.cursor()

            # Use a parameterized query to prevent SQL injection
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()

            if user:
                # Delete the user.  Limit deletion to only the user's own record.
                cursor.execute("DELETE FROM users WHERE email = ?", (email,))
                db.commit()
                flash('You have been successfully unsubscribed.', 'success')
            else:
                flash('Email address not found in our database.', 'info')

        except sqlite3.Error as e:
            print(f"Database error: {e}")  # Log the error
            flash('An error occurred during unsubscription. Please try again.', 'error')

        return render_template('unsubscribe.html', csrf_token=generate_csrf_token())

    return render_template('unsubscribe.html', csrf_token=generate_csrf_token())


@app.route('/')
def index():
    return render_template('index.html')


if __name__ == '__main__':
    # Ensure the database file exists.  This is important for initial setup.
    if not os.path.exists(DATABASE):
        init_db()  # Create the database and tables if they don't exist.

    app.run(debug=True)

