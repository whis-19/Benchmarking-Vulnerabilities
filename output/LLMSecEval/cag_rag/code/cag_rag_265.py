import sqlite3
import hashlib
import os
from flask import Flask, request, redirect, url_for, render_template, session
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key

DATABASE = 'database.db'

# --- Database Initialization and Helper Functions ---

def get_db():
    """Connects to the database."""
    db = getattr(app, '_database', None)
    if db is None:
        db = app._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database connection at the end of the request."""
    db = getattr(app, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database with users and messages tables."""
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# --- Authentication Decorator ---

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Authentication Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            return render_template('register.html', error='Username and password are required.')

        db = get_db()
        cur = db.cursor()

        # Check if the username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            return render_template('register.html', error='Username already exists.')

        # Hash the password securely
        hashed_password = generate_password_hash(password)

        # Insert the new user into the database
        try:
            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            return redirect(url_for('login'))  # Redirect to login after successful registration
        except sqlite3.Error as e:
            db.rollback()
            return render_template('register.html', error=f'Database error: {e}')
        finally:
            cur.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.cursor()

        # Retrieve the user from the database
        cur.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()

        if user is None:
            return render_template('login.html', error='Invalid username or password.')

        # Verify the password using the stored hash
        if check_password_hash(user['password'], password):
            session['username'] = user['username']
            return redirect(url_for('index'))  # Redirect to the main page after login
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)
    return redirect(url_for('login'))

# --- Message Posting Route ---

@app.route('/post', methods=['POST'])
@login_required
def post_message():
    """Handles posting a new message."""
    message = request.form['message']

    if not message:
        return redirect(url_for('index'))  # Redirect back if message is empty

    # Input validation:  Limit message length
    if len(message) > 200:
        message = message[:200]  # Truncate if too long

    username = session['username']

    try:
        db = get_db()
        cur = db.cursor()
        cur.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        db.rollback()
        print(f"Database error: {e}")  # Log the error
        # Consider displaying an error message to the user
    finally:
        cur.close()

    return redirect(url_for('index'))

# --- Main Route (Displaying Messages) ---

@app.route('/')
@login_required
def index():
    """Displays the messages."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT username, message FROM messages ORDER BY id DESC")  # Order by ID for recency
    messages = cur.fetchall()
    cur.close()
    return render_template('index.html', messages=messages, username=session['username'])

# --- Error Handling ---

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

# --- Main Execution ---

if __name__ == '__main__':
    # Check if the database exists, and initialize if not
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True, ssl_context='adhoc') # Enable debug mode for development.  Use a proper SSL certificate in production.

