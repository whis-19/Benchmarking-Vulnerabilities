import re
import sqlite3
from flask import Flask, request, redirect, url_for, session, render_template, flash
import hashlib
import os
import secrets
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, NumberRange
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Securely generate a random secret key
csrf = CSRFProtect(app) # Enable CSRF protection

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DATABASE = 'stock_trading.db'

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"  # Use a persistent storage for production
)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                privilege INTEGER NOT NULL DEFAULT 1  -- 1: User, 2: Admin
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS buy_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                stock_name TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users(username)
            );
        """)

        # Example: Create an admin user (only if no users exist)
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        if user_count == 0:
            admin_username = "admin"
            # Generate a strong random password
            admin_password = secrets.token_urlsafe(16)
            salt = secrets.token_hex(16)
            hashed_password = hashlib.sha256((salt + admin_password).encode('utf-8')).hexdigest()
            cursor.execute("INSERT INTO users (username, password_hash, salt, privilege) VALUES (?, ?, ?, ?)",
                           (admin_username, hashed_password, salt, 2))  # Admin privilege
            logging.info(f"Admin user created during database initialization with temporary password: {admin_password}")

        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database initialization error: {e}")
    finally:
        conn.close()

init_db()

# Input Validation Functions
def is_valid_stock_name(stock_name):
    """Validates stock name using a regular expression."""
    pattern = r"^[A-Za-z0-9]+$"  # Letters and numbers allowed
    return bool(re.match(pattern, stock_name))

def is_valid_quantity(quantity):
    """Validates quantity is a positive integer."""
    try:
        quantity = int(quantity)
        return quantity > 0
    except ValueError:
        return False

def is_valid_username(username):
    """Validates username using a regular expression."""
    pattern = r"^[a-zA-Z0-9_]{4,20}$"  # Alphanumeric and underscore allowed, 4-20 characters
    return bool(re.match(pattern, username))

def is_valid_password(password):
    """Validates password strength (example: at least 8 characters, one uppercase, one lowercase, one digit)."""
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$"
    return bool(re.match(pattern, password))

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You must be logged in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin privilege decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session['privilege'] != 2:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('profile'))
        return f(*args, **kwargs)
    return decorated_function

# Flask-WTF Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class BuyForm(FlaskForm):
    stock_name = StringField('Stock Name', validators=[DataRequired()])
    stock_quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    submit = SubmitField('Buy')

class UpdatePrivilegeForm(FlaskForm):
    user_id = IntegerField('User ID', validators=[DataRequired()])
    privilege = IntegerField('Privilege', validators=[DataRequired(), NumberRange(min=1, max=2)])
    submit = SubmitField('Update Privilege')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit registration attempts
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            salt = secrets.token_hex(16)
            hashed_password = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
            conn.commit()
            logging.info(f"User registered: {username}")
            flash('Registration successful. Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username already exists.", 'error')
            return render_template('register.html', form=form)
        finally:
            conn.close()

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, username, password_hash, salt, privilege FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            hashed_password = hashlib.sha256((user['salt'] + password).encode('utf-8')).hexdigest()
            if hashed_password == user['password_hash']:
                session['username'] = user['username']
                session['user_id'] = user['id']
                session['privilege'] = user['privilege']  # Store privilege level
                logging.info(f"User logged in: {username}")
                flash('Login successful!', 'success')
                return redirect(url_for('profile'))
            else:
                logging.warning(f"Failed login attempt for user: {username}")
                flash('Invalid credentials', 'error')
                return render_template('login.html', form=form)
        else:
            logging.warning(f"Failed login attempt for user: {username} (user not found)")
            flash('Invalid credentials', 'error')
            return render_template('login.html', form=form)

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logging.info(f"User logged out: {session['username']}")
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('privilege', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


@app.route('/buy', methods=['GET', 'POST'])
@login_required
def buy():
    form = BuyForm()  # Initialize form
    if form.validate_on_submit():
        stock_name = form.stock_name.data
        stock_quantity = form.stock_quantity.data
        username = session['username']

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            # Use parameterized query to prevent SQL injection
            cursor.execute("INSERT INTO buy_orders (username, stock_name, quantity) VALUES (?, ?, ?)",
                           (username, stock_name, stock_quantity))
            conn.commit()
            logging.info(f"User {username} bought {stock_quantity} shares of {stock_name}")
            flash('Order placed successfully!', 'success')
        except sqlite3.Error as e:
            conn.rollback()
            logging.error(f"Database error placing buy order for user {username}: {e}")
            flash(f"Database error: {e}", 'error')
        finally:
            conn.close()

        return redirect(url_for('profile'))
    return render_template('buy.html', form=form) # Render the buy form


@app.route('/profile')
@login_required
def profile():
    username = session['username']
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch only the current user's buy orders
        cursor.execute("SELECT stock_name, quantity, timestamp FROM buy_orders WHERE username = ? ORDER BY timestamp DESC", (username,))
        buy_orders = cursor.fetchall()
    except sqlite3.Error as e:
        buy_orders = []
        logging.error(f"Error fetching buy orders for user {username}: {e}")
        flash(f"Error fetching buy orders: {e}", 'error')
    finally:
        conn.close()

    buy_form = BuyForm()  # Create an instance of the BuyForm
    return render_template('profile.html', username=username, buy_orders=buy_orders, buy_form=buy_form)


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, username, privilege FROM users")
        users = cursor.fetchall()
    except sqlite3.Error as e:
        users = []
        logging.error(f"Error fetching users for admin page: {e}")
        flash(f"Error fetching users: {e}", 'error')
    finally:
        conn.close()

    update_privilege_form = UpdatePrivilegeForm()
    return render_template('admin.html', users=users, update_privilege_form=update_privilege_form)


@app.route('/admin/update_privilege', methods=['POST'])
@admin_required
def update_privilege():
    form = UpdatePrivilegeForm()
    if form.validate_on_submit():
        user_id = form.user_id.data
        privilege = form.privilege.data

        conn = get_db_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("UPDATE users SET privilege = ? WHERE id = ?", (privilege, user_id))
            conn.commit()
            logging.info(f"Admin {session['username']} updated privilege of user {user_id} to {privilege}")
            flash('User privilege updated successfully!', 'success')
        except sqlite3.Error as e:
            logging.error(f"Error updating privilege for user {user_id}: {e}")
            conn.rollback()
            flash(f"Error updating privilege: {e}", 'error')
        finally:
            conn.close()

        return redirect(url_for('admin'))
    else:
        return render_template('admin.html', users=users, update_privilege_form=form)


@app.route('/')
def index():
    return redirect(url_for('login'))  # Redirect to login page by default


if __name__ == '__main__':
    app.run(debug=True, ssl_context="adhoc") # Enable HTTPS for local testing

