import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template, abort
import secrets
import os
import bcrypt  # For password hashing
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, IntegerField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange, Regexp, ValidationError
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from flask_session import Session  # For server-side session management
from datetime import timedelta

app = Flask(__name__)

# --- Configuration ---
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Use a strong, randomly generated key
app.config['DATABASE'] = 'stock_trading.db'
app.config['SESSION_TYPE'] = 'filesystem'  # Use server-side session storage (filesystem)
app.config['SESSION_PERMANENT'] = True  # Make sessions permanent
app.config['SESSION_USE_SIGNER'] = True  # Securely sign the session cookie
app.config['SESSION_KEY_PREFIX'] = 'session:'  # Add a prefix to session keys
app.config['SESSION_FILE_DIR'] = 'flask_session'  # Directory to store session files
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session timeout

# --- Logging ---
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
app.logger.addHandler(logging.StreamHandler())  # Also log to the console
app.logger.setLevel(logging.INFO)

# --- Extensions ---
csrf = CSRFProtect(app)  # Enable CSRF protection
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day, 50 per hour"])  # Rate limiting
Session(app)  # Initialize Flask-Session

# --- Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = app.config['DATABASE']

def get_db_connection():
    """Connects to the database."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    """Initializes the database (creates tables if they don't exist)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS buy_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            stock_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    conn.commit()
    conn.close()

# Call init_db when the app starts
with app.app_context():
    init_db()

# --- Forms ---
def validate_username(form, field):
    """Custom username validation."""
    if not re.match(r"^[a-zA-Z0-9_]+$", field.data):
        raise ValidationError("Username must contain only alphanumeric characters and underscores.")

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20), validate_username])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BuyForm(FlaskForm):
    stock_name = StringField('Stock Name', validators=[DataRequired(), Length(max=10), Regexp(r'^[A-Za-z]+$', message='Stock name must contain only letters')])
    stock_quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1, max=1000000)])
    submit = SubmitField('Buy')


# --- Password Hashing Functions ---
def hash_password(password):
    """Hashes a password using bcrypt."""
    salt = bcrypt.gensalt()  # Generate a random salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt.decode('utf-8')  # Store both hash and salt

def check_password(password, hashed_password, salt):
    """Checks if a password matches a hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False  # Handle potential errors like invalid salt


# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register():
    """Handles user registration."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Hash the password
        hashed_password, salt = hash_password(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
                           (username, hashed_password, salt))
            conn.commit()
            conn.close()
            app.logger.info(f"User registered: {username}")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            # Handle username already exists error
            form.username.errors.append("Username already exists.")
            app.logger.warning(f"Registration failed: Username already exists - {username}")
            return render_template('register.html', form=form)
        except sqlite3.Error as e:
            app.logger.exception("Database error during registration")
            abort(500)  # Internal Server Error

    return render_template('register.html', form=form)


@app.route('/buy', methods=['POST'])
def buy_stock():
    """Handles the buy order submission."""
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    form = BuyForm()
    if form.validate_on_submit():
        username = session['username']  # Get username from session
        stock_name = form.stock_name.data
        stock_quantity = form.stock_quantity.data

        # Database interaction (using parameterized queries to prevent SQL injection)
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO buy_orders (username, stock_name, quantity) VALUES (?, ?, ?)",
                           (username, stock_name, stock_quantity))
            conn.commit()
            conn.close()
            app.logger.info(f"User {username} bought {stock_quantity} shares of {stock_name}")
        except sqlite3.Error as e:
            app.logger.exception("Database error during buy_stock")
            abort(500)  # Internal Server Error

        # Redirect to the profile page
        return redirect(url_for('profile'))
    return render_template('buy.html', form=form)


@app.route('/profile')
def profile():
    """Displays the user's profile page."""
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM buy_orders WHERE username = ?", (username,))
    buy_orders = cursor.fetchall()
    conn.close()

    buy_form = BuyForm()  # Pass the buy form to the template
    return render_template('profile.html', username=username, buy_orders=buy_orders, buy_form=buy_form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Limit login attempts
def login():
    """Handles user login."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT password, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password = user['password']
            stored_salt = user['salt']
            if check_password(password, stored_password, stored_salt):
                session['username'] = username
                session.regenerate()  # Regenerate session ID after login
                app.logger.info(f"User logged in: {username}")
                return redirect(url_for('profile'))
            else:
                form.password.errors.append("Invalid username or password")
                app.logger.warning(f"Login failed: Invalid password for user {username}")
                return render_template('login.html', form=form)
        else:
            form.username.errors.append("Invalid username or password")
            app.logger.warning(f"Login failed: Invalid username {username}")
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    """Logs the user out."""
    username = session.get('username')
    session.pop('username', None)
    app.logger.info(f"User logged out: {username}")
    return redirect(url_for('login'))


@app.route('/')
def index():
    """Renders the index page."""
    return render_template('index.html')

@app.errorhandler(500)
def internal_server_error(e):
    """Handles 500 Internal Server Error."""
    app.logger.exception("Internal Server Error")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handles rate limit errors."""
    app.logger.warning("Rate limit exceeded")
    return "Rate limit exceeded. Please try again later.", 429


if __name__ == '__main__':
    # NEVER use debug=True in production!
    app.run(debug=True)

