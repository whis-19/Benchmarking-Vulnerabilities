import os
import secrets
import hashlib
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from functools import wraps
import configparser
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)

# Configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Secret Key (for session management and CSRF protection)
app.config['SECRET_KEY'] = config['app']['secret_key'] or secrets.token_hex(24)  # Generate if not in config

# Database Configuration
DATABASE = config['database']['path']

# Logging Configuration
logging.basicConfig(filename=config['logging']['path'], level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Content Security Policy (CSP)
@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self';"  # Example CSP - customize as needed
    return response

# Database Connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
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

# Authentication Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Forms for CSRF Protection ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit registration
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db()
        cursor = db.cursor()

        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('register.html', form=form)

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Insert the new user into the database
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            logging.info(f"User registered: {username}")
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            db.rollback()
            flash('An error occurred during registration. Please try again.', 'danger')
            logging.error(f"Database error during registration: {e}")
            return render_template('register.html', form=form)

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db()
        cursor = db.cursor()

        # Retrieve user from the database
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Login successful!', 'success')
            logging.info(f"User logged in: {username}")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            logging.warning(f"Failed login attempt: {username}")
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


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
    return redirect(url_for('index'))

# --- Error Handling ---

@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"404 error: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f"500 error: {e}")
    return render_template('500.html'), 500

# --- Initialization ---

if __name__ == '__main__':
    # Check if the database exists, and if not, initialize it.
    if not os.path.exists(DATABASE):
        print("Database not found. Initializing...")
        init_db()
    app.run(debug=True)

