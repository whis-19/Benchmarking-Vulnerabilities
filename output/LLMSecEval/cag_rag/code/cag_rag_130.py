import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
import secrets
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Securely generate a secret key

DATABASE = 'stock_trading.db'

# --- Database Initialization and User Management ---
def get_db():
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        # Enable foreign key constraints for relational integrity
        db.execute("PRAGMA foreign_keys = ON")
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Create the database and tables if they don't exist.  Call this once on deployment.
# init_db()


def create_user(username, password):
    db = get_db()
    hashed_password = generate_password_hash(password)
    try:
        with db: # Use context manager for transaction
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    except sqlite3.IntegrityError:
        return False  # Username already exists
    return True

def authenticate_user(username, password):
    db = get_db()
    user = db.execute("SELECT id, username, password FROM users WHERE username = ?", (username,)).fetchone()
    if user and check_password_hash(user['password'], password):
        return {'id': user['id'], 'username': user['username']}
    return None

# --- Authentication Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- CSRF Token Generation ---
def generate_csrf_token():
    session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    if 'csrf_token' not in session or token != session['csrf_token']:
        return False
    return True

# --- Routes ---
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
        user = authenticate_user(username, password)

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('stock_view'))
        else:
            return render_template('login.html', error="Invalid credentials")

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
    return redirect(url_for('stock_view'))

@app.route('/stock_view')
@login_required
def stock_view():
    db = get_db()
    user_id = session['user_id']
    stocks = db.execute("SELECT id, stock_name, quantity FROM stock_orders WHERE user_id = ?", (user_id,)).fetchall()
    return render_template('stock_view.html', stocks=stocks)

@app.route('/buy_order', methods=['GET', 'POST'])
@login_required
def buy_order():
    if request.method == 'POST':
        stock_name = request.form['stock_name']
        quantity = request.form['quantity']
        csrf_token = request.form['csrf_token']

        # Validate CSRF token
        if not validate_csrf_token(csrf_token):
            return render_template('error.html', message="CSRF token validation failed.")

        # Input validation:  Check for empty strings and valid integer
        if not stock_name or not quantity:
            return render_template('buy_order.html', error="Stock name and quantity are required.", csrf_token=generate_csrf_token())

        try:
            quantity = int(quantity)
            if quantity <= 0:
                return render_template('buy_order.html', error="Quantity must be a positive integer.", csrf_token=generate_csrf_token())
        except ValueError:
            return render_template('buy_order.html', error="Invalid quantity. Must be an integer.", csrf_token=generate_csrf_token())

        db = get_db()
        user_id = session['user_id']

        try:
            with db: # Use context manager for transaction
                db.execute("INSERT INTO stock_orders (user_id, stock_name, quantity) VALUES (?, ?, ?)", (user_id, stock_name, quantity))
        except sqlite3.Error as e:
            print(f"Database error: {e}") # Log the error
            return render_template('buy_order.html', error="Database error occurred.", csrf_token=generate_csrf_token())

        return redirect(url_for('stock_view'))

    return render_template('buy_order.html', csrf_token=generate_csrf_token())


if __name__ == '__main__':
    # Ensure the database file exists
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True)

