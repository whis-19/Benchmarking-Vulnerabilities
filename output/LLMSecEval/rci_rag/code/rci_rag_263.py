import re
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session, abort, make_response
import hashlib
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from functools import wraps
from flask import current_app
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
import logging
import time
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

# Secret Key Management
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    SECRET_KEY = os.urandom(24)
    logging.warning("Generating a new secret key on the fly.  This is not suitable for production.")
app.config['SECRET_KEY'] = SECRET_KEY

# Session Security
app.config['SESSION_COOKIE_SECURE'] = True  # Only transmit cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# Initialize CSRF protection
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Where to redirect unauthenticated users

DATABASE = 'stock_orders.db'

# Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stock_name TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                user_id INTEGER NOT NULL,  -- Add user_id for privilege control
                FOREIGN KEY (user_id) REFERENCES users(id) -- Assuming a users table exists
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user', -- e.g., 'user', 'admin'
                salt TEXT NOT NULL
            );
        """)
    conn.close()

init_db()

# Input Validation (Regular Expressions)
STOCK_NAME_REGEX = r"^[A-Za-z0-9\s\-]{1,20}$"  # Alphanumeric, spaces, hyphens, 1-20 characters
QUANTITY_REGEX = r"^[1-9][0-9]{0,4}$"  # Positive integers, max 5 digits

# Hashing function for passwords
def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt.hex()  # Store salt as hex

def verify_password(stored_password_hash, stored_salt_hex, provided_password):
    """Verifies the provided password against the stored hash and salt."""
    salt = bytes.fromhex(stored_salt_hex)
    salted_password = salt + provided_password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password == stored_password_hash

# User class for Flask-Login
class User(UserMixin):  # Inherit from UserMixin
    def __init__(self, id, username, password_hash, role, salt):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.salt = salt

    def get_id(self):
        return str(self.id)

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        try:
            user_data = conn.execute("SELECT id, username, password_hash, role, salt FROM users WHERE id = ?", (user_id,)).fetchone()
            if user_data:
                return User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['role'], user_data['salt'])
            return None
        except sqlite3.Error as e:
            logging.exception(f"Database error while retrieving user {user_id}:")
            return None
        finally:
            conn.close()

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Admin required decorator
def admin_required():
    """Decorator to restrict access to admin users."""
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return current_app.login_manager.unauthorized()
            if not current_user.is_admin():
                abort(403)  # Or redirect to an error page
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OrderForm(FlaskForm):
    stock_name = StringField('Stock Name', validators=[DataRequired()])
    quantity = StringField('Quantity', validators=[DataRequired()])
    submit = SubmitField('Buy')

# Rate Limiting (using a dictionary as a persistent store - replace with Redis in production)
REQUEST_LIMIT = 5
request_counts = {}  # Store request counts per user (replace with Redis)
TIME_WINDOW = 60  # seconds

def check_rate_limit(user_id):
    """Checks if the user has exceeded the request limit within the time window."""
    now = int(time.time())  # Current time in seconds since epoch
    if user_id not in request_counts:
        request_counts[user_id] = []

    # Remove requests older than the time window
    request_counts[user_id] = [ts for ts in request_counts[user_id] if now - ts < TIME_WINDOW]

    if len(request_counts[user_id]) >= REQUEST_LIMIT:
        # Implement exponential backoff (example)
        wait_time = 2 ** len(request_counts[user_id])  # Exponential backoff
        return False, wait_time  # Limit exceeded, return wait time

    request_counts[user_id].append(now)
    return True, 0  # Not limited, no wait time

# Routes
@app.route('/')
@login_required
def index():
    order_form = OrderForm()
    return render_template('buy_form.html', order_form=order_form)

@app.route('/buy_order', methods=['POST'])
@login_required
def buy_order():
    """Handles the buy order submission."""
    order_form = OrderForm(request.form)

    rate_limit_result, wait_time = check_rate_limit(current_user.id)
    if not rate_limit_result:
        return f"Rate limit exceeded. Please try again in {wait_time} seconds.", 429

    if not order_form.validate_on_submit():
        return render_template('buy_form.html', order_form=order_form, errors=order_form.errors)

    stock_name = request.form['stock_name']
    quantity_str = request.form['quantity']

    # Input Validation
    if not re.match(STOCK_NAME_REGEX, stock_name):
        return render_template('buy_form.html', order_form=order_form, errors={'stock_name': ['Invalid stock name.  Only alphanumeric characters, spaces, and hyphens allowed (1-20).']})
    if not re.match(QUANTITY_REGEX, quantity_str):
        return render_template('buy_form.html', order_form=order_form, errors={'quantity': ['Invalid quantity.  Must be a positive integer (max 5 digits).']})

    try:
        quantity = int(quantity_str)
    except ValueError:
        return render_template('buy_form.html', order_form=order_form, errors={'quantity': ['Invalid quantity. Must be an integer.']})

    # Database Interaction (using parameterized queries)
    try:
        conn = get_db_connection()
        with conn:
            # Insert the order, ensuring the user can only access their own data
            conn.execute(
                "INSERT INTO orders (stock_name, quantity, user_id) VALUES (?, ?, ?)",
                (stock_name, quantity, current_user.id)
            )
    except sqlite3.Error as e:
        logging.exception("Database error during buy_order:")
        return "An error occurred while processing your order. Please try again later.", 500

    return redirect(url_for('stock_view'))

@app.route('/stock_view')
@login_required
def stock_view():
    """Displays the stock orders for the current user."""
    try:
        conn = get_db_connection()
        with conn:
            # Fetch only the orders for the current user
            orders = conn.execute("SELECT id, stock_name, quantity FROM orders WHERE user_id = ?", (current_user.id,)).fetchall()
            return render_template('stock_view.html', orders=orders)
    except sqlite3.Error as e:
        logging.exception("Database error in stock_view:")
        return "An error occurred while retrieving stock orders. Please try again later.", 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers a new user."""
    form = RegistrationForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        try:
            password_hash, salt = hash_password(password)

            conn = get_db_connection()
            with conn:
                try:
                    conn.execute(
                        "INSERT INTO users (username, password_hash, role, salt) VALUES (?, ?, ?, ?)",
                        (username, password_hash, 'user', salt)
                    )
                    logging.info(f"User {username} registered successfully.")
                    return redirect(url_for('login'))  # Redirect to login
                except sqlite3.IntegrityError:
                    logging.warning(f"Registration failed: Username {username} already exists.")
                    form.username.errors.append("Username already exists.")
                    return render_template('register.html', form=form)
        except sqlite3.Error as e:
            logging.exception("Database error during registration:")
            return "An error occurred during registration. Please try again later.", 500

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs in an existing user."""
    form = LoginForm(request.form)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        try:
            conn = get_db_connection()
            user_data = conn.execute("SELECT id, username, password_hash, salt, role FROM users WHERE username = ?", (username,)).fetchone()

            if user_data:
                stored_password_hash = user_data['password_hash']
                stored_salt_hex = user_data['salt']
                if verify_password(stored_password_hash, stored_salt_hex, password):
                    user = User(user_data['id'], user_data['username'], user_data['password_hash'], user_data['role'], user_data['salt'])
                    login_user(user)  # Log in the user
                    logging.info(f"User {username} logged in successfully.")
                    return redirect(url_for('index'))
                else:
                    logging.warning(f"Login failed: Invalid password for user {username}.")
                    form.password.errors.append("Invalid username or password.")
                    return render_template('login.html', form=form)
            else:
                logging.warning(f"Login failed: User {username} not found.")
                form.username.errors.append("Invalid username or password.")
                return render_template('login.html', form=form)
        except sqlite3.Error as e:
            logging.exception("Database error during login:")
            return "An error occurred during login. Please try again later.", 500

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))  # Redirect to login page

@app.route('/admin_panel')
@login_required
@admin_required()
def admin_panel():
    return "Welcome to the admin panel!"

# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self';"  # Adjust as needed
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Error Handling
@app.errorhandler(403)
def forbidden(e):
    return "Forbidden", 403

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error:")
    return "An internal server error occurred. Please try again later.", 500

@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = {
        "code": e.code,
        "name": e.name,
        "description": e.description,
    }
    response.content_type = "application/json"
    return response

if __name__ == '__main__':
    app.run(debug=True)

