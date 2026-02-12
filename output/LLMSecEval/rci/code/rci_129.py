import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template
import secrets
import os
import logging
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Length
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Use environment variable for secret key, fallback to a generated one
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)

# Session Security Configuration
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

# Initialize Bcrypt and CSRFProtect
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Database setup (using SQLite for simplicity - consider PostgreSQL for production)
DATABASE = 'stock_trading.db'

def get_db_connection():
    """Connects to the database."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def init_db():
    """Initializes the database (creates tables if they don't exist)."""
    db = get_db_connection()
    with open('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()
    db.close()

# Create the database and tables if they don't exist
if not os.path.exists(DATABASE):
    init_db()

# Define Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BuyStockForm(FlaskForm):
    stock_name = StringField('Stock Name', validators=[DataRequired()])
    stock_quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1, max=1000)])
    submit = SubmitField('Buy')

# Rate Limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]  # Example limits
)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def register():
    """Handles user registration."""
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            db = get_db_connection()
            cursor = db.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            db.close()
            logging.info(f"User {username} registered successfully.")
            return redirect(url_for('login'))  # Redirect to login after registration
        except sqlite3.IntegrityError:
            db.rollback()
            db.close()
            logging.warning(f"Registration failed: Username {username} already exists.")
            return render_template('register.html', form=form, error="Username already exists")

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Example limit for login attempts
def login():
    """Handles user login."""
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        db.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            session['username'] = username
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('profile'))
        else:
            logging.warning(f"Login failed for user {username}: Invalid credentials.")
            return render_template('login.html', form=form, error="Invalid credentials")

    return render_template('login.html', form=form)


@app.route('/buy', methods=['GET', 'POST'])
def buy_stock():
    """Handles the buy stock order."""
    if 'username' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    form = BuyStockForm()
    if form.validate_on_submit():
        username = session['username']
        stock_name = form.stock_name.data
        stock_quantity = form.stock_quantity.data

        # Database interaction (using parameterized queries to prevent SQL injection)
        try:
            db = get_db_connection()
            cursor = db.cursor()

            # Insert the buy order into the database
            cursor.execute(
                "INSERT INTO buy_orders (username, stock_name, quantity) VALUES (?, ?, ?)",
                (username, stock_name, stock_quantity)
            )
            db.commit()
            db.close()
            logging.info(f"User {username} bought {stock_quantity} shares of {stock_name}.")
            return redirect(url_for('profile'))  # Redirect to the profile page

        except sqlite3.Error as e:
            logging.error(f"Database error for user {username}, stock {stock_name}, quantity {stock_quantity}: {e}")
            db.rollback()
            db.close()
            return render_template('error.html', message="An unexpected error occurred. Please try again later.")

    return render_template('buy.html', form=form)


@app.route('/profile')
def profile():
    """Displays the user's profile page."""
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    try:
        db = get_db_connection()
        cursor = db.cursor()

        # Fetch user's buy orders (example)
        cursor.execute("SELECT * FROM buy_orders WHERE username = ?", (username,))
        buy_orders = cursor.fetchall()

        db.close()

        # Sanitize stock_name using bleach
        for order in buy_orders:
            order['stock_name'] = bleach.clean(order['stock_name'])

        return render_template('profile.html', username=username, buy_orders=buy_orders)

    except sqlite3.Error as e:
        logging.error(f"Database error fetching profile for user {username}: {e}")
        return render_template('error.html', message="An unexpected error occurred. Please try again later.")


@app.route('/logout')
def logout():
    """Logs the user out."""
    username = session.pop('username', None)
    if username:
        logging.info(f"User {username} logged out.")
    return redirect(url_for('login'))


@app.route('/')
def index():
    """Renders the index page."""
    return render_template('index.html')


# Content Security Policy (CSP)
@app.after_request
def add_csp_header(response):
    csp = "default-src 'self'; " \
          "script-src 'self' 'unsafe-inline'; " \
          "style-src 'self' 'unsafe-inline'; " \
          "img-src 'self' data:; " \
          "font-src 'self';"
    response.headers['Content-Security-Policy'] = csp
    return response


if __name__ == '__main__':
    # Ensure the database exists before running the app
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True, ssl_context='adhoc')  # Disable debug mode in production!  Use a proper SSL certificate.

