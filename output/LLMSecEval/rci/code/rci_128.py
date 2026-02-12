import sqlite3
import secrets
import bcrypt  # Use bcrypt for password hashing
from flask import Flask, request, render_template, g, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
from flask_talisman import Talisman

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Securely generate a secret key for session management
app.config['SECRET_KEY'] = secrets.token_hex(32)  # Use a strong, random key

# Session Security
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protect against CSRF

# Database configuration
DATABASE = 'stock_trading.db'

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)

# Initialize Talisman for Content Security Policy (CSP) and HTTPS
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net'],  # Example: Allow scripts from a CDN
    'style-src': ['\'self\'', 'https://cdn.jsdelivr.net'], # Example: Allow styles from a CDN
    'img-src': '\'self\' data:',
    'font-src': '\'self\'',
    'connect-src': '\'self\'',
}

talisman = Talisman(app, content_security_policy=csp, force_https=True)


def get_db():
    """Connects to the database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database (creates tables if they don't exist)."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Example schema.sql (create tables)
# CREATE TABLE IF NOT EXISTS users (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     username TEXT UNIQUE NOT NULL,
#     password TEXT NOT NULL
# );
#
# CREATE TABLE IF NOT EXISTS stock_purchases (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     user_id INTEGER NOT NULL,
#     stock_name TEXT NOT NULL,
#     quantity INTEGER NOT NULL,
#     purchase_date DATETIME DEFAULT CURRENT_TIMESTAMP,
#     FOREIGN KEY (user_id) REFERENCES users (id)
# );


def hash_password(password):
    """Hashes the password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8') # Store as string

def create_user(username, password):
    """Creates a new user in the database with a bcrypt hashed password."""
    db = get_db()
    hashed_password = hash_password(password)
    try:
        db.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                   (username, hashed_password))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False

def verify_password(username, password):
    """Verifies the password against the stored bcrypt hash."""
    db = get_db()
    user = db.execute("SELECT id, password FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['user_id'] = user['id']  # Store user ID in session
            return True
    return False

def login_required(f):
    """Decorator to require login for a route."""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if create_user(username, password):
            logging.info(f"User registered: {username}")
            return redirect(url_for('login'))
        else:
            logging.warning(f"Registration failed: Username already exists: {username}")
            return render_template('register.html', form=form, error="Username already exists")
    return render_template('register.html', form=form)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if verify_password(username, password):
            logging.info(f"User logged in: {username}")
            return redirect(url_for('index'))  # Redirect to the main page after login
        else:
            logging.warning(f"Login failed: Invalid username or password for {username}")
            return render_template('login.html', form=form, error="Invalid username or password")
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    username = None
    db = get_db()
    user_id = session.get('user_id')
    if user_id:
        user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if user:
            username = user['username']

    session.pop('user_id', None)
    logging.info(f"User logged out: {username}")
    return redirect(url_for('login'))

@app.route('/')
@login_required
@limiter.limit("10 per minute")
def index():
    """Main page (requires login)."""
    return render_template('index.html', form=BuyStockForm())  # Replace with your actual index page

def buy_function(stock_name):
    """
    Simulates the actual buying process.  This is a placeholder.
    In a real application, this would interact with a stock exchange API.
    """
    # In a real application, you would interact with a stock exchange API here.
    # This is a placeholder.
    logging.info(f"Simulating buying stock: {stock_name}")
    # Add error handling and logging in a real application.
    return True  # Or False if the purchase failed

class BuyStockForm(FlaskForm):
    stock_name = StringField('Stock Name', validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Buy')

    def validate_stock_name(form, field):
        allowed_stocks = ["AAPL", "GOOG", "MSFT"]  # Replace with your actual stock symbols
        if field.data not in allowed_stocks:
            raise ValidationError("Invalid stock name.")

@app.route('/buy', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def buy_stock():
    """Handles the stock purchase request."""
    form = BuyStockForm(request.form)
    if form.validate_on_submit():
        stock_name = form.stock_name.data
        quantity = form.quantity.data
        user_id = session['user_id']

        db = get_db()
        try:
            # Insert the purchase record into the database
            db.execute("INSERT INTO stock_purchases (user_id, stock_name, quantity) VALUES (?, ?, ?)",
                       (user_id, stock_name, quantity))
            db.commit()

            # Call the buy_function to actually attempt the purchase
            if buy_function(stock_name):
                logging.info(f"Successfully purchased {quantity} shares of {stock_name} for user {user_id}")
                return render_template('index.html', form=form, message=f"Successfully purchased {quantity} shares of {stock_name}.")
            else:
                # Revert the database transaction if the buy fails
                db.rollback()
                logging.error(f"Failed to purchase stock {stock_name} for user {user_id}")
                return render_template('index.html', form=form, error="Failed to purchase stock. Please try again.")

        except sqlite3.Error as e:
            db.rollback()
            logging.exception(f"Database error while purchasing stock: {e}")
            return render_template('index.html', form=form, error="An error occurred while processing your request. Please try again.")
    else:
        logging.warning(f"Invalid form submission: {form.errors}")
        return render_template('index.html', form=form, error=form.errors)


if __name__ == '__main__':
    # Initialize the database (create tables)
    with app.app_context():
        init_db()

    # Run the Flask application
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)  # Disable debug mode in production!

