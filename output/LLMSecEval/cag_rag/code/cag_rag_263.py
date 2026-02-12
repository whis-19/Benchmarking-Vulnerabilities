import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
import os
from functools import wraps
import secrets
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Generate a random secret key

DATABASE = 'stock_trading.db'

# --- Database Initialization ---
def get_db():
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with open('schema.sql', 'r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database if it doesn't exist
if not os.path.exists(DATABASE):
    init_db()

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Hashing Function ---
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    
    # Use PBKDF2HMAC for strong password hashing
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Iterations - adjust for security/performance tradeoff
    ).hex()
    
    return salt, hashed_password

def verify_password(stored_salt, stored_hash, password):
    salt, hashed_password = hash_password(password, stored_salt)
    return hashed_password == stored_hash

# --- Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Input validation (example - more robust validation needed)
        if not username or not password:
            return render_template('register.html', error="Username and password are required.")

        db = get_db()
        cur = db.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return render_template('register.html', error="Username already exists.")

        # Hash the password
        salt, hashed_password = hash_password(password)

        # Insert the user into the database
        try:
            cur.execute("INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)", (username, salt, hashed_password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            db.rollback()
            return render_template('register.html', error=f"Database error: {e}")
        finally:
            cur.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.cursor()

        # Retrieve user from the database
        cur.execute("SELECT id, username, password_salt, password_hash FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()

        if user:
            stored_salt = user['password_salt']
            stored_hash = user['password_hash']

            if verify_password(stored_salt, stored_hash, password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('stock_view'))
            else:
                return render_template('login.html', error='Invalid credentials')
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/buy_order', methods=['POST'])
@login_required
def buy_order():
    if request.method == 'POST':
        stock_name = request.form['stock_name']
        quantity = request.form['quantity']

        # Input validation (important!)
        if not stock_name or not quantity:
            return render_template('index.html', error="Stock name and quantity are required.")

        try:
            quantity = int(quantity)
            if quantity <= 0:
                return render_template('index.html', error="Quantity must be a positive integer.")
        except ValueError:
            return render_template('index.html', error="Invalid quantity. Must be an integer.")

        db = get_db()
        cur = db.cursor()

        try:
            # Get the current user's ID from the session
            user_id = session['user_id']

            # Use parameterized query to prevent SQL injection
            cur.execute("INSERT INTO orders (user_id, stock_name, quantity) VALUES (?, ?, ?)", (user_id, stock_name, quantity))
            db.commit()
        except sqlite3.Error as e:
            db.rollback()
            return render_template('index.html', error=f"Database error: {e}")
        finally:
            cur.close()

        return redirect(url_for('stock_view'))

@app.route('/stock_view')
@login_required
def stock_view():
    db = get_db()
    cur = db.cursor()

    # Fetch orders for the current user only
    user_id = session['user_id']
    cur.execute("SELECT stock_name, quantity FROM orders WHERE user_id = ?", (user_id,))
    orders = cur.fetchall()
    cur.close()

    return render_template('stock_view.html', orders=orders)

if __name__ == '__main__':
    app.run(debug=True)

