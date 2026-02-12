import sqlite3
import secrets
import hashlib
from flask import Flask, request, render_template, g, redirect, url_for, session

app = Flask(__name__)

# Securely generate a secret key for session management
app.secret_key = secrets.token_hex(32)  # Use a strong, random key

# Database configuration
DATABASE = 'stock_trading.db'

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
#     password TEXT NOT NULL,
#     salt TEXT NOT NULL
# );
#
# CREATE TABLE IF NOT EXISTS stock_transactions (
#     id INTEGER PRIMARY KEY AUTOINCREMENT,
#     user_id INTEGER NOT NULL,
#     stock_name TEXT NOT NULL,
#     quantity INTEGER NOT NULL,
#     transaction_date DATETIME DEFAULT CURRENT_TIMESTAMP,
#     FOREIGN KEY (user_id) REFERENCES users (id)
# );


def hash_password(password, salt):
    """Hashes the password using SHA-256 with a salt."""
    salted_password = salt.encode('utf-8') + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password

def create_user(username, password):
    """Creates a new user in the database with a securely hashed password."""
    db = get_db()
    salt = secrets.token_hex(16)  # Generate a random salt
    hashed_password = hash_password(password, salt)
    try:
        db.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
                   (username, hashed_password, salt))
        db.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False

def verify_password(username, password):
    """Verifies the password against the stored hash."""
    db = get_db()
    user = db.execute("SELECT id, password, salt FROM users WHERE username = ?", (username,)).fetchone()
    if user:
        stored_password = user['password']
        salt = user['salt']
        hashed_password = hash_password(password, salt)
        if hashed_password == stored_password:
            return user['id']  # Return user ID on successful login
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if create_user(username, password):
            return redirect(url_for('login'))
        else:
            return render_template('register.html', error="Username already exists")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_id = verify_password(username, password)
        if user_id:
            session['user_id'] = user_id  # Store user ID in session
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user_id' in session:
        return render_template('index.html')
    else:
        return redirect(url_for('login'))

def buy_function(stock_name):
    """
    Simulates the actual buying process.  This is a placeholder.
    In a real application, this would interact with a stock exchange API.
    """
    # In a real application, you would interact with a stock exchange API here.
    # This is just a placeholder.
    print(f"Simulating buying stock: {stock_name}")
    # Add error handling and logging in a real application.
    return True  # Indicate success or failure

def buy_stock(stock_name, quantity):
    """
    Handles the stock buying process: inserts into the database and calls buy_function.
    """
    if 'user_id' not in session:
        return "Error: User not logged in.", 401  # Unauthorized

    user_id = session['user_id']

    try:
        quantity = int(quantity)  # Validate quantity as an integer
        if quantity <= 0:
            return "Error: Quantity must be a positive integer.", 400  # Bad Request
    except ValueError:
        return "Error: Invalid quantity.  Must be an integer.", 400  # Bad Request

    db = get_db()
    try:
        # Use parameterized queries to prevent SQL injection
        db.execute("INSERT INTO stock_transactions (user_id, stock_name, quantity) VALUES (?, ?, ?)",
                   (user_id, stock_name, quantity))
        db.commit()

        # Call the buy_function to actually attempt to buy the stock
        if buy_function(stock_name):
            return "Stock purchase successful!", 200  # OK
        else:
            # Revert the database transaction if the buy fails
            db.rollback()
            return "Error: Stock purchase failed.", 500  # Internal Server Error

    except sqlite3.Error as e:
        db.rollback()
        print(f"Database error: {e}")  # Log the error
        return "Error: Database error during stock purchase.", 500  # Internal Server Error

@app.route('/buy', methods=['POST'])
def buy():
    """
    Handles the buy request from the form.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    stock_name = request.form.get('stock_name')
    quantity = request.form.get('quantity')

    if not stock_name or not quantity:
        return "Error: Stock name and quantity are required.", 400  # Bad Request

    result, status_code = buy_stock(stock_name, quantity)
    return result, status_code

@app.route('/transactions')
def transactions():
    """
    Displays the user's transaction history.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    db = get_db()
    transactions = db.execute("SELECT stock_name, quantity, transaction_date FROM stock_transactions WHERE user_id = ? ORDER BY transaction_date DESC", (user_id,)).fetchall()
    return render_template('transactions.html', transactions=transactions)


if __name__ == '__main__':
    # Initialize the database (create tables)
    with app.app_context():
        init_db()

    # Run the Flask application
    app.run(debug=True)

