import re
import sqlite3
from flask import Flask, request, redirect, url_for, render_template, g
import hashlib
import os

app = Flask(__name__)

# Database Configuration
DATABASE = 'stock_orders.db'
# Secret key for session management (replace with a strong, randomly generated key)
app.secret_key = os.urandom(24)

# Rate limiting (example: 5 requests per minute)
REQUEST_LIMIT = 5
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}  # Store request counts per user (IP address)

def get_db():
    """Connects to the database.  Creates it if it doesn't exist."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # Enable foreign key constraints for data integrity
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database schema."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database if it doesn't exist on startup
try:
    init_db()
except sqlite3.OperationalError:
    # Database already exists
    pass

# Input Validation Regular Expressions
STOCK_NAME_REGEX = r"^[a-zA-Z0-9]+$"  # Alphanumeric only
QUANTITY_REGEX = r"^[1-9][0-9]*$"  # Positive integers only

def validate_stock_name(stock_name):
    """Validates the stock name using a regular expression."""
    if not re.match(STOCK_NAME_REGEX, stock_name):
        return False
    return True

def validate_quantity(quantity):
    """Validates the quantity using a regular expression."""
    if not re.match(QUANTITY_REGEX, str(quantity)):  # Convert to string for regex
        return False
    return True

def check_rate_limit(user_ip):
    """Checks if the user has exceeded the request limit."""
    import time
    now = time.time()
    if user_ip not in user_request_counts:
        user_request_counts[user_ip] = []

    # Remove requests older than the window
    user_request_counts[user_ip] = [ts for ts in user_request_counts[user_ip] if ts > now - REQUEST_WINDOW]

    if len(user_request_counts[user_ip]) >= REQUEST_LIMIT:
        return True  # Rate limit exceeded

    user_request_counts[user_ip].append(now)
    return False  # Rate limit not exceeded

@app.route('/')
def index():
    """Renders the buy order form."""
    return render_template('buy_order_form.html')

@app.route('/buy_order', methods=['POST'])
def buy_order():
    """Handles the buy order submission."""
    user_ip = request.remote_addr  # Get user's IP address for rate limiting

    if check_rate_limit(user_ip):
        return "Rate limit exceeded. Please try again later.", 429  # HTTP 429 Too Many Requests

    stock_name = request.form['stock_name']
    quantity = request.form['quantity']

    # Input Validation
    if not validate_stock_name(stock_name):
        return "Invalid stock name.  Must be alphanumeric.", 400  # HTTP 400 Bad Request
    if not validate_quantity(quantity):
        return "Invalid quantity. Must be a positive integer.", 400  # HTTP 400 Bad Request

    try:
        quantity = int(quantity)  # Convert quantity to integer
    except ValueError:
        return "Invalid quantity. Must be an integer.", 400

    try:
        db = get_db()
        # Use parameterized query to prevent SQL injection
        cursor = db.cursor()
        cursor.execute("INSERT INTO orders (stock_name, quantity) VALUES (?, ?)", (stock_name, quantity))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error
        return "An error occurred while processing your order.", 500  # HTTP 500 Internal Server Error

    return redirect(url_for('stock_view'))

@app.route('/stock_view')
def stock_view():
    """Displays the stock view (currently just a placeholder)."""
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT stock_name, quantity FROM orders")
        orders = cursor.fetchall()
        return render_template('stock_view.html', orders=orders)
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return "An error occurred while retrieving stock data.", 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers a new user."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Basic username/password validation (add more robust checks)
        if not (3 <= len(username) <= 20 and 8 <= len(password) <= 64):
            return "Invalid username or password.  Username must be 3-20 characters, password 8-64.", 400

        # Hash the password
        hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        try:
            db = get_db()
            cursor = db.cursor()
            # Insert the user into the database
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            return "Registration successful!  Please log in."
        except sqlite3.IntegrityError:
            return "Username already exists.", 409  # HTTP 409 Conflict
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return "An error occurred during registration.", 500

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs in an existing user."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if result:
                hashed_password = result[0]
                # Verify the password
                if hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed_password:
                    # Authentication successful
                    return "Login successful!"  # Replace with proper session management
                else:
                    return "Invalid username or password.", 401  # HTTP 401 Unauthorized
            else:
                return "Invalid username or password.", 401
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return "An error occurred during login.", 500

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)

