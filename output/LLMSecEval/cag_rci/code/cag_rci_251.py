import os
import secrets
import hashlib
from flask import Flask, render_template, request, session, redirect, url_for, flash, g
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from functools import wraps
# from werkzeug.security import generate_password_hash, check_password_hash  # Replaced with bcrypt
from passlib.hash import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import logging  # Import the logging module
from datetime import timedelta
import sqlite3

app = Flask(__name__)

# Initialize Flask-WTF
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Security Headers with Talisman
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', '\'nonce-{nonce}\''],  # Use nonce!
    'style-src': ['\'self\'', '\'nonce-{nonce}\'', 'https://cdn.jsdelivr.net'],  # Example CDN
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\''
}

talisman = Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['script-src', 'style-src'])

# Configuration (Never hardcode secrets!)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(24))  # Use environment variable
app.config['DATABASE'] = 'users.db'  # Example database name
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Prevent CSRF for cross-site requests

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["5 per minute"]  # Adjust as needed
)

# Database setup (Example using SQLite - for production, use a more robust database)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database if it doesn't exist (run this once)
# with app.app_context():
#     init_db()


# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Login')


# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_id') is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def make_session_permanent():
    session.permanent = True


# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session['username'])


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db()
        cur = db.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if user and user['password_hash'] and bcrypt.verify(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            session.regenerate() # Regenerate the session ID
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')

        return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    session.clear()  # Invalidate the entire session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = LoginForm()  # Reuse LoginForm for simplicity, adjust as needed
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Check if username already exists
        db = get_db()
        cur = db.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cur.fetchone()

        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)

        # Hash the password
        password_hash = bcrypt.hash(password)

        # Insert the new user into the database
        try:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.username" in str(e):
                flash('Username already exists. Please choose a different one.', 'danger')
            else:
                print(f"Database error: {e}")  # Log the error
                flash('An error occurred during registration. Please try again.', 'danger')

    return render_template('register.html', form=form)


# Example route requiring CSRF protection
@app.route('/protected', methods=['POST'])
@login_required
def protected():
    # Process the protected action here
    flash('Action successful!', 'success')
    return redirect(url_for('index'))


# Error Handling
import logging

logging.basicConfig(filename='app.log', level=logging.ERROR)  # Configure logging

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the exception
    return render_template('500.html'), 500

# Example database schema (schema.sql)
# Create a file named schema.sql in the same directory as your Python script
# to initialize the database.

-- Create the users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

-- Add an index on the username column for faster lookups
-- Indexes improve query performance, especially for frequently accessed columns.
CREATE INDEX idx_username ON users (username);

if __name__ == '__main__':
    app.run(debug=True)

