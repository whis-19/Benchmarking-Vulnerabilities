import re
import html
from flask import Flask, request, redirect, url_for, render_template, session
import sqlite3
import time
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Securely generate a random secret key

# Database setup (example using SQLite)
DATABASE = 'messages.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with app.open_resource('schema.sql', mode='r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()

# Initialize the database (create tables) if it doesn't exist
try:
    with open(DATABASE, 'r'):
        pass
except FileNotFoundError:
    init_db()


# Input validation functions
def is_valid_username(username):
    """Validates the username using a regular expression."""
    # Allow alphanumeric characters, underscores, and hyphens, with length between 3 and 20
    pattern = r"^[a-zA-Z0-9_-]{3,20}$"
    return re.match(pattern, username) is not None

def is_valid_message(message):
    """Validates the message using a regular expression."""
    # Allow alphanumeric characters, spaces, and common punctuation, with length between 1 and 500
    pattern = r"^[a-zA-Z0-9\s.,?!:;'-]{1,500}$"
    return re.match(pattern, message) is not None

# Rate limiting (example: 5 requests per minute)
REQUEST_LIMIT = 5
REQUEST_WINDOW = 60  # seconds
user_request_counts = {}  # Store request counts per user

def is_rate_limited(username):
    """Checks if the user has exceeded the request limit."""
    now = time.time()
    if username not in user_request_counts:
        user_request_counts[username] = []

    # Remove requests older than the window
    user_request_counts[username] = [ts for ts in user_request_counts[username] if now - ts < REQUEST_WINDOW]

    if len(user_request_counts[username]) >= REQUEST_LIMIT:
        return True
    else:
        user_request_counts[username].append(now)
        return False

# Authentication functions (example using password hashing)
def hash_password(password):
    """Hashes the password using SHA-256."""
    # Salt the password for added security
    salt = os.urandom(16)  # Generate a random salt
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password, salt.hex()  # Store salt as hex string

def verify_password(stored_hash, password, salt_hex):
    """Verifies the password against the stored hash."""
    salt = bytes.fromhex(salt_hex)
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).hexdigest()
    return hashed_password == stored_hash

# Database interaction function
def insert_user_message_in_db(username, message):
    """Inserts the user message into the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error (don't expose to user)
        # Handle the error appropriately (e.g., display a generic error message)
        return False  # Indicate failure
    finally:
        conn.close()
    return True  # Indicate success

def get_messages_from_db():
    """Retrieves all messages from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, message FROM messages ORDER BY id DESC")
    messages = cursor.fetchall()
    conn.close()
    return messages

# Routes
@app.route('/', methods=['GET', 'POST'])
def main_page():
    """Handles the main page, displaying messages and handling new posts."""
    if request.method == 'POST':
        if 'username' not in session:
            return redirect(url_for('login'))

        username = session['username']
        message = request.form.get('message')

        # Validate input
        if not is_valid_message(message):
            return render_template('main.html', error="Invalid message format.", messages=get_messages_from_db())

        if is_rate_limited(username):
            return render_template('main.html', error="Rate limit exceeded. Please wait.", messages=get_messages_from_db())

        # Insert message into the database
        if insert_user_message_in_db(username, message):
            return redirect(url_for('main_page'))  # Redirect to refresh the page
        else:
            return render_template('main.html', error="Failed to save message.", messages=get_messages_from_db())

    # GET request: display the main page with messages
    messages = get_messages_from_db()
    return render_template('main.html', messages=messages)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate username
        if not is_valid_username(username):
            return render_template('login.html', error="Invalid username format.")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT hash, salt FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            stored_hash = user['hash']
            salt_hex = user['salt']
            if verify_password(stored_hash, password, salt_hex):
                session['username'] = username
                return redirect(url_for('main_page'))
            else:
                return render_template('login.html', error="Invalid username or password.")
        else:
            return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate username
        if not is_valid_username(username):
            return render_template('register.html', error="Invalid username format.")

        # Basic password validation (at least 8 characters)
        if len(password) < 8:
            return render_template('register.html', error="Password must be at least 8 characters.")

        # Hash the password
        hashed_password, salt = hash_password(password)

        # Store the username, hashed password, and salt in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, hash, salt) VALUES (?, ?, ?)", (username, hashed_password, salt))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))  # Redirect to login page after successful registration
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', error="Username already exists.")
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            conn.close()
            return render_template('register.html', error="Registration failed. Please try again.")

    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logs the user out."""
    session.pop('username', None)
    return redirect(url_for('main_page'))

# Error handling (example)
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)

