import re
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session
import hashlib
import os
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for session management and CSRF
csrf = CSRFProtect(app)  # Enable CSRF protection

DATABASE = 'stock_data.db'
# Load the salt from a file or database (DO NOT GENERATE ON EVERY START)
SALT_FILE = 'salt.key'  # Consider storing the salt in a more secure location, such as a database or a dedicated secrets management system.  Ensure this file has appropriate permissions (e.g., only readable by the application user).

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configure rate limiting
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day, 50 per hour"]  # Example limits
)


def load_salt():
    """Loads the salt from a file.  Creates a new salt if the file doesn't exist."""
    try:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    except FileNotFoundError:
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
        logging.info("Generated and saved a new salt.")  # Log salt generation
    return salt

SALT = load_salt()


# --- Database Initialization and Helper Functions ---

def get_db_connection():
    """Connects to the database."""
    conn = sqlite3.connect(DATABASE) # Consider using a connection pool for better performance
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
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'  -- 'user' or 'admin'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            stock_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

# Create an admin user if none exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    admin_exists = cursor.fetchone()[0]
    if admin_exists == 0:
        # Hash the admin password (replace 'admin_password' with a strong password)
        admin_password = os.environ.get("ADMIN_PASSWORD", "admin_password")  # Get from env var
        if not admin_password:
            logging.error("ADMIN_PASSWORD environment variable not set! Using default 'admin_password'.")
            admin_password = "admin_password" # Fallback, but log a warning
        hashed_password = generate_password_hash(admin_password) # Use Werkzeug for password hashing
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ('admin', hashed_password, 'admin'))
        conn.commit()
        logging.info("Created admin user.")
    conn.close()


# --- Input Validation ---

def validate_stock_name(stock_name):
    """Validates the stock name using a regular expression."""
    pattern = r"^[A-Za-z]+$"  # Only letters allowed
    return bool(re.match(pattern, stock_name))

def validate_quantity(quantity):
    """Validates the quantity (must be a positive integer)."""
    try:
        quantity = int(quantity)
        return quantity > 0
    except ValueError:
        return False

def sanitize_input(input_string):
    """Sanitizes input to prevent HTML injection."""
    # This is a basic example; consider using a library like Bleach for more robust sanitization
    return re.sub(r"[<>]", "", input_string)  # Remove < and > characters

# --- Authentication ---

#def hash_password(password):
#    """Hashes the password using SHA-256 and a salt."""
#    return hashlib.sha256(SALT + password.encode('utf-8')).hexdigest()

#def verify_password(stored_hash, password):
#    """Verifies the password against the stored hash."""
#    hashed_password = hash_password(password)
#    return hashed_password == stored_hash

# --- User Management (Example - Replace with a proper authentication system) ---

# In a real application, use a proper session management system.
#USER_ID = None  # Store the logged-in user's ID here

# --- Authentication ---

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Limit login attempts
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        # Use parameterized query to prevent SQL injection
        cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password): # Use Werkzeug to check password
            # Use session to store user ID
            session['user_id'] = user['id']
            logging.info(f"User {username} logged in successfully.")
            return redirect(url_for('stock_view'))
        else:
            logging.warning(f"Failed login attempt for user {username}.")
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = get_username_from_session()
    session.pop('user_id', None)  # Remove user ID from session
    logging.info(f"User {username} logged out.")
    return redirect(url_for('login'))

# --- Helper function to get username from session ---
def get_username_from_session():
    user_id = session.get('user_id')
    if user_id:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        if user:
            return user['username']
    return "Unknown"

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/buy_order', methods=['POST'])
@login_required
def buy_order():
    """Handles the buy order submission."""
    #if USER_ID is None:
    #    return redirect(url_for('login'))  # Redirect if not logged in

    stock_name = request.form['stock_name']
    quantity = request.form['quantity']

    # Input validation and sanitization
    if not validate_stock_name(stock_name):
        logging.warning(f"Invalid stock name submitted: {stock_name}")
        return "Invalid stock name. Only letters allowed."  # Or render an error template
    stock_name = sanitize_input(stock_name) # Sanitize after validation
    if not validate_quantity(quantity):
        logging.warning(f"Invalid quantity submitted: {quantity}")
        return "Invalid quantity. Must be a positive integer."  # Or render an error template

    # Database interaction (using parameterized query)
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO stock_orders (user_id, stock_name, quantity) VALUES (?, ?, ?)",
                       (session['user_id'], stock_name, int(quantity)))  # Convert quantity to integer
        conn.commit()
        conn.close()
        username = get_username_from_session()
        logging.info(f"User {username} placed a buy order for {quantity} shares of {stock_name}.")
    except sqlite3.Error as e:
        logging.exception("Database error while processing buy order.") # Log the full exception
        return "An error occurred while processing your order."  # Or render an error template

    return redirect(url_for('stock_view'))

@app.route('/stock_view')
@login_required
def stock_view():
    """Displays the stock orders for the logged-in user."""
    #if USER_ID is None:
    #    return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Limit user access to their own data
    cursor.execute("SELECT stock_name, quantity FROM stock_orders WHERE user_id = ?", (session['user_id'],))
    orders = cursor.fetchall()
    conn.close()

    return render_template('stock_view.html', orders=orders)

@app.route('/buy_form')
@login_required
def buy_form():
    #if USER_ID is None:
    #    return redirect(url_for('login'))
    return render_template('buy_form.html')

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")
    return render_template('500.html'), 500

# --- Templates (Example) ---

# Create these templates in a 'templates' folder:

# templates/login.html
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
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"><br><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password"><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""

# templates/buy_form.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Buy Stock</title>
</head>
<body>
    <h1>Buy Stock</h1>
    <form method="post" action="{{ url_for('buy_order') }}">
        <label for="stock_name">Stock Name:</label><br>
        <input type="text" id="stock_name" name="stock_name"><br><br>
        <label for="quantity">Quantity:</label><br>
        <input type="number" id="quantity" name="quantity"><br><br>
        <input type="submit" value="Buy">
    </form>
</body>
</html>
"""

# templates/stock_view.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Stock Orders</title>
</head>
<body>
    <h1>Stock Orders</h1>
    <ul>
        {% for order in orders %}
            <li>Stock: {{ order['stock_name'] }}, Quantity: {{ order['quantity'] }}</li>
        {% endfor %}
    </ul>
    <a href="{{ url_for('buy_form') }}">Buy More Stock</a> | <a href="{{ url_for('logout') }}">Logout</a>
</body>
</html>
"""

# templates/500.html
"""
<!DOCTYPE html>
<html>
<head>
    <title>Internal Server Error</title>
</head>
<body>
    <h1>Internal Server Error</h1>
    <p>An unexpected error occurred. Please try again later.</p>
</body>
</html>
"""

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

