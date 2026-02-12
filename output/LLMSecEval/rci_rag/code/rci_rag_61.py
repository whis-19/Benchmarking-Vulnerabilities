import os
import secrets
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
from bleach import clean
import logging
from dotenv import load_dotenv
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(16)  # Get from environment or generate
app.config['DATABASE'] = os.environ.get('DATABASE_URL') or 'users.db'  # Get from environment or default
app.config['BCRYPT_LOG_ROUNDS'] = int(os.environ.get('BCRYPT_LOG_ROUNDS', 12)) # Get bcrypt rounds from env or default
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access to the cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF

# Enable CSRF protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"], # Example limits
    storage_uri="memory://" # Use a persistent store like Redis for production
)

# Content Security Policy
talisman = Talisman(app, content_security_policy={
    'default-src': '\'self\'',
    'script-src': '\'self\'',  # Add 'unsafe-inline' if needed, but avoid if possible
    'style-src': '\'self\'',
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
})


# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup
DATABASE = app.config['DATABASE']

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def create_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_login INTEGER DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()

create_table()


# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20),
                                                   Regexp(r'^[a-zA-Z0-9_]+$',
                                                          message='Username must contain only letters, numbers, and underscores')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8),
                                                   Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]+$',
                                                          message='Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class FirstLoginForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8),
                                                   Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]+$',
                                                          message='Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Update Password')


@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute") # Example rate limit for login
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,)) # Parameterized query to prevent SQL injection
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user['password_hash']
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
                session['username'] = username
                logging.info(f"User {username} logged in successfully.")
                return redirect(url_for('dashboard'))
            else:
                logging.warning(f"Failed login attempt for user {username}.")
                return render_template('login.html', form=form, error='Invalid credentials')
        else:
            logging.warning(f"Failed login attempt for user {username}: User not found.")
            return render_template('login.html', form=form, error='Invalid credentials')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,)) # Parameterized query to prevent SQL injection
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            logging.warning(f"Registration attempt with existing username: {username}")
            return render_template('register.html', form=form, error='Username already exists')

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=app.config['BCRYPT_LOG_ROUNDS'])).decode('utf-8')

        # Insert the new user into the database
        try:
            cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', # Parameterized query to prevent SQL injection
                           (username, hashed_password))
            conn.commit()
            conn.close()
            logging.info(f"New user registered: {username}")
            return redirect(url_for('login'))  # Redirect to login after successful registration
        except sqlite3.IntegrityError:
            conn.close()
            logging.error(f"Integrity error during registration for username: {username}")
            return render_template('register.html', form=form, error='Username already exists') # Handle potential race conditions

    return render_template('register.html', form=form)


@app.route('/first_login', methods=['GET', 'POST'])
def first_login():
    username = session.get('username')
    if not username:
        return redirect(url_for('login'))

    form = FirstLoginForm()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT first_login FROM users WHERE username = ?', (username,)) # Parameterized query to prevent SQL injection
    user = cursor.fetchone()

    if not user or user['first_login'] == 0:
        conn.close()
        return redirect(url_for('dashboard'))  # Not a first-time login

    if form.validate_on_submit():
        new_password = form.new_password.data

        # Hash the new password using bcrypt
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt(rounds=app.config['BCRYPT_LOG_ROUNDS'])).decode('utf-8')

        # Update the password and set first_login to 0
        cursor.execute('UPDATE users SET password_hash = ?, first_login = 0 WHERE username = ?', # Parameterized query to prevent SQL injection
                       (hashed_password, username))
        conn.commit()
        conn.close()
        logging.info(f"User {username} completed first login and changed password.")
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('first_login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        safe_username = clean(username)  # Sanitize username for display

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT first_login FROM users WHERE username = ?', (username,)) # Parameterized query to prevent SQL injection
        user = cursor.fetchone()
        conn.close()

        if user and user['first_login'] == 1:
            return redirect(url_for('first_login'))
        else:
            return render_template('dashboard.html', username=safe_username)
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    username = session.get('username')
    if username:
        logging.info(f"User {username} logged out.")
    session.pop('username', None)
    return redirect(url_for('login'))

@app.errorhandler(429)
def ratelimit_handler(e):
    logging.warning(f"Rate limit exceeded: {request.remote_addr}")
    return "Rate limit exceeded. Please try again later.", 429


@app.errorhandler(500)
def internal_server_error(e):
    # Log the error
    logging.exception("Internal Server Error")
    # Return a user-friendly error page
    return render_template('500.html'), 500


if __name__ == '__main__':
    # Ensure the database file exists and has proper permissions.
    if not os.path.exists(DATABASE):
        create_table()

    # Consider using a production-ready WSGI server like Gunicorn or uWSGI
    # Use environment variables for host and port
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_RUN_PORT', 5000))
    app.run(debug=True, host=host, port=port)

