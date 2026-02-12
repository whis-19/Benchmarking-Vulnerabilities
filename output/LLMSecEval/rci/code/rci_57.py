import sqlite3
import bcrypt
import secrets
import os
from flask import Flask, render_template, request, redirect, url_for, session, abort
import re
import logging  # Import the logging module
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from werkzeug.exceptions import HTTPException, NotFound, InternalServerError

app = Flask(__name__)

# --- Securely Load Secret Key from Environment Variable ---
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    # Generate a secure key if one isn't found in the environment
    app.secret_key = secrets.token_hex(32)
    print("WARNING: No FLASK_SECRET_KEY found in environment.  Using a generated key.  This is NOT recommended for production.")

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- CSRF Protection ---
csrf = CSRFProtect(app)

# --- Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="memory://"  # Use a persistent storage for production
)

DATABASE = 'users.db'

# --- Database Initialization ---
def create_table():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

create_table()

# --- Hashing Function (bcrypt) ---
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt.decode('utf-8')

def verify_password(password, hashed_password, salt):
    hashed_password_bytes = hashed_password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password_bytes)

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=20), Regexp(r'^[a-zA-Z0-9_.-]+$', message="Username must contain only alphanumeric characters, underscores, periods, or hyphens.")])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- User Authentication Functions ---
def register_user(username, password):
    """Registers a new user in the database."""

    try:
        hashed_password, salt = hash_password(password)
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", (username, hashed_password.decode('utf-8'), salt))
        conn.commit()
        conn.close()
        logging.info(f"User registered: {username}")
        return True, None  # Registration successful
    except sqlite3.IntegrityError:
        logging.warning(f"Registration failed: Username already exists - {username}")
        return False, "Username already exists"
    except Exception as e:
        logging.exception("Error during registration:")  # Log the full exception
        return False, "An unexpected error occurred during registration.  Please contact support."


def authenticate_user(username, password):
    """Authenticates a user against the database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if user:
        hashed_password, salt = user
        if verify_password(password, hashed_password, salt):
            logging.info(f"User authenticated: {username}")
            return username
        else:
            logging.warning(f"Authentication failed: Incorrect password for user - {username}")
            return None
    else:
        logging.warning(f"Authentication failed: User not found - {username}")
        return None

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Flask Routes ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = authenticate_user(username, password)

        if user:
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', form=form, error='Invalid username or password')

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        success, message = register_user(username, password)

        if success:
            return redirect(url_for('login'))
        else:
            return render_template('register.html', form=form, error=message)

    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    username = session['username']
    return render_template('dashboard.html', username=username)

@app.route('/logout')
@login_required
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# --- Error Handling ---
@app.errorhandler(NotFound)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(InternalServerError)
def internal_server_error(e):
    logging.exception("Internal Server Error:")  # Log the exception
    return render_template('500.html'), 500

# Generic error handler
@app.errorhandler(Exception)
def handle_exception(e):
    # Pass through HTTP errors
    if isinstance(e, HTTPException):
        return e

    # Log the exception
    logging.exception("Unhandled Exception:")

    # Return a generic error page
    return render_template("500.html"), 500

# --- Template Files ---
# Create the following HTML files in a 'templates' folder:
# - login.html
# - register.html
# - dashboard.html
# - 404.html
# - 500.html

# login.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        {{ form.csrf_token }}
        <label for="username">Username:</label><br>
        {{ form.username }}<br><br>
        <label for="password">Password:</label><br>
        {{ form.password }}<br><br>
        {{ form.submit }}
    </form>
    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
</body>
</html>
"""

# register.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Register</title>
</head>
<body>
    <h1>Register</h1>
    {% if error %}
        <p style="color: red;">{{ error }}</p>
    {% endif %}
    <form method="post">
        {{ form.csrf_token }}
        <label for="username">Username:</label><br>
        {{ form.username }}<br><br>
        <label for="password">Password:</label><br>
        {{ form.password }}<br><br>
        <label for="confirm_password">Confirm Password:</label><br>
        {{ form.confirm_password }}<br><br>
        {{ form.submit }}
    </form>
    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
</body>
</html>
"""

# dashboard.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
</head>
<body>
    <h1>Welcome, {{ username }}!</h1>
    <p>This is your dashboard.</p>
    <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# 404.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on the server.</p>
</body>
</html>
"""

# 500.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>500 Internal Server Error</title>
</head>
<body>
    <h1>500 Internal Server Error</h1>
    <p>An internal server error occurred.</p>
</body>
</html>
"""

if __name__ == '__main__':
    # NEVER USE debug=True IN PRODUCTION!
    app.run(debug=True, host="0.0.0.0")

