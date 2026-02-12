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
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Access columns by name
    return db

def init_db():
    """Initializes the database with users and messages tables."""
    with app.app_context():
        db = get_db()
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def insert_user_message_in_db(username, message):
    """Inserts a user message into the database using a parameterized query."""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        db.rollback()
    finally:
        db.close()

def get_all_messages():
    """Retrieves all messages from the database."""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("SELECT username, message FROM messages ORDER BY id DESC")
        messages = cursor.fetchall()
        return messages
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        db.close()

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
            return render_template('register.html', error="Username and password are required.")

        db = get_db()
        try:
            cursor = db.cursor()
            # Hash the password using Werkzeug's secure hashing
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            db.rollback()
            return render_template('register.html', error="Username already exists.")
        except sqlite3.Error as e:
            db.rollback()
            print(f"Database error: {e}")
            return render_template('register.html', error="An error occurred during registration.")
        finally:
            db.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['username'] = user['username']
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error="Invalid username or password.")
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return render_template('login.html', error="An error occurred during login.")
        finally:
            db.close()

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """Handles user logout."""
    session.pop('username', None)
    return redirect(url_for('index'))

# --- Main Application Routes ---

@app.route('/')
def index():
    """Displays the main page with messages."""
    messages = get_all_messages()
    return render_template('index.html', messages=messages, username=session.get('username'))

@app.route('/post', methods=['POST'])
@login_required
def post():
    """Handles posting a new message."""
    message = request.form['message']
    username = session['username']  # Get username from session

    # Input validation:  Basic length check.  More robust validation is recommended.
    if not message or len(message) > 200:  # Limit message length
        return render_template('index.html', messages=get_all_messages(), error="Message cannot be empty or exceed 200 characters.", username=username)

    insert_user_message_in_db(username, message)
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Check if the database exists, and if not, initialize it.
    if not os.path.exists(DATABASE):
        init_db()

    app.run(debug=True, ssl_context='adhoc') # Enable debug mode and HTTPS

