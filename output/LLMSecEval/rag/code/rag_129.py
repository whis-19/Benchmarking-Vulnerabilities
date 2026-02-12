import re
import sqlite3
import hashlib
import os
from flask import Flask, request, redirect, url_for, session, render_template, g

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

DATABASE = 'stock_trading.db'

# --- Database Initialization and Connection ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Security Utilities ---

def hash_password(password):
    """Hashes the password using SHA-256 with a salt."""
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return salt.hex() + ":" + hashed_password

def verify_password(stored_hash, password):
    """Verifies the password against the stored hash (salt:hash)."""
    try:
        salt, hashed_password = stored_hash.split(":")
        salt = bytes.fromhex(salt)
        salted_password = salt + password.encode('utf-8')
        return hashlib.sha256(salted_password).hexdigest() == hashed_password
    except ValueError:
        return False  # Invalid hash format

# --- Input Validation ---

def validate_stock_name(stock_name):
    """Validates the stock name using a regular expression."""
    pattern = r"^[A-Za-z]+$"  # Only letters allowed
    return bool(re.match(pattern, stock_name))

def validate_quantity(quantity):
    """Validates the quantity to be a positive integer."""
    try:
        quantity = int(quantity)
        return quantity > 0
    except ValueError:
        return False

# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validate username (example: alphanumeric, 3-20 characters)
        if not re.match(r"^[a-zA-Z0-9]{3,20}$", username):
            return render_template('register.html', error="Invalid username format.")

        # Validate password (example: at least 8 characters, one uppercase, one lowercase, one digit)
        if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$", password):
            return render_template('register.html', error="Password must be at least 8 characters with one uppercase, one lowercase, and one digit.")

        hashed_password = hash_password(password)

        db = get_db()
        try:
            # Use parameterized query to prevent SQL injection
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, hashed_password, 'user'))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('register.html', error="Username already exists.")

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        user = db.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,)).fetchone()

        if user and verify_password(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']  # Store user role in session
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))


@app.route('/profile')
def profile():
    if 'user_id' in session:
        username = session['username']
        db = get_db()

        # Fetch user's buy orders.  Limit to the user's own data.
        buy_orders = db.execute("SELECT stock_name, quantity FROM buy_orders WHERE user_id = ?", (session['user_id'],)).fetchall()

        return render_template('profile.html', username=username, buy_orders=buy_orders)
    else:
        return redirect(url_for('login'))


@app.route('/buy', methods=['GET', 'POST'])
def buy():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        stock_name = request.form['stock_name']
        stock_quantity = request.form['stock_quantity']

        # Input validation
        if not validate_stock_name(stock_name):
            return render_template('buy.html', error="Invalid stock name.")
        if not validate_quantity(stock_quantity):
            return render_template('buy.html', error="Invalid quantity.")

        stock_quantity = int(stock_quantity) # Convert to integer after validation

        db = get_db()
        try:
            # Use parameterized query to prevent SQL injection
            db.execute("INSERT INTO buy_orders (user_id, stock_name, quantity) VALUES (?, ?, ?)",
                       (session['user_id'], stock_name, stock_quantity))
            db.commit()
            return redirect(url_for('profile'))
        except sqlite3.Error as e:
            return render_template('buy.html', error=f"Database error: {e}")

    return render_template('buy.html')


# --- Admin Route (Example of Role-Based Access Control) ---

@app.route('/admin')
def admin():
    if 'user_id' in session and session['role'] == 'admin':
        db = get_db()
        # Example: Fetch all users (careful with this in production!)
        users = db.execute("SELECT id, username, role FROM users").fetchall()
        return render_template('admin.html', users=users)
    else:
        return "Unauthorized", 403  # HTTP 403 Forbidden


if __name__ == '__main__':
    # Create the database and tables if they don't exist.  Only do this ONCE.
    # You might want to use a migration tool for production.
    try:
        init_db()
    except sqlite3.OperationalError:
        print("Database already exists, skipping initialization.")

    app.run(debug=True)

