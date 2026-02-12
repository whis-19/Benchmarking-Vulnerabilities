from flask import Flask, render_template, request, redirect, url_for, session, escape
import sqlite3
import re
import logging
import os
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
import bleach  # For sanitization
import secrets # For generating secure random values

app = Flask(__name__)

# Generate a strong, random secret key
# Use secrets.token_hex for better security and readability
app.secret_key = secrets.token_hex(24)
csrf = CSRFProtect(app) # Enable CSRF protection

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Log errors and above

# Database setup (example)
DATABASE = 'messages.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:  # Create schema.sql if it doesn't exist
        conn.executescript(f.read())
    conn.commit()
    conn.close()

# Create schema.sql if it doesn't exist
try:
    with open('schema.sql', 'r'):
        pass
except FileNotFoundError:
    with open('schema.sql', 'w') as f:
        f.write("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL
        );
        """)
    init_db()

# Input validation functions
def is_valid_username(username):
    # Allow only alphanumeric characters and underscores, 3-20 characters long
    # \A and \Z ensure the entire string matches the pattern
    pattern = r"\A[a-zA-Z0-9_]{3,20}\Z"
    return bool(re.match(pattern, username))

def is_valid_message(message):
    # Allow alphanumeric characters, spaces, and some punctuation, 1-200 characters long
    # \A and \Z ensure the entire string matches the pattern
    pattern = r"\A[a-zA-Z0-9\s.,!?]{1,200}\Z"
    return bool(re.match(pattern, message))

def insert_user_message_in_db(username, message):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return False  # Indicate failure
    return True

@app.route('/', methods=['GET'])
def index():
    try:
        conn = get_db_connection()
        # Configure the database user with the minimum necessary permissions.
        messages = conn.execute("SELECT id, username, message FROM messages ORDER BY id DESC").fetchall()
        conn.close()

        # Escape messages for display to prevent XSS
        escaped_messages = []
        for message in messages:
            escaped_messages.append({
                'id': message['id'],
                'username': escape(message['username']),
                'message': escape(message['message'])
            })

        return render_template('index.html', messages=escaped_messages)
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        return render_template('error.html', error_message="An error occurred while retrieving messages.") # Generic error

@app.route('/post', methods=['POST'])
def post():
    if request.method == 'POST':
        username = request.form.get('username')
        message = request.form.get('message')

        # Validate inputs
        if not username or not message:
            return render_template('error.html', error_message="Username and message are required.") # Generic error
        if not is_valid_username(username):
            return render_template('error.html', error_message="Invalid username format.") # Generic error
        if not is_valid_message(message):
            return render_template('error.html', error_message="Invalid message format.") # Generic error

        # Sanitize the message
        message = bleach.clean(message)

        # Insert into database
        if insert_user_message_in_db(username, message):
            return redirect(url_for('index'))
        else:
            return render_template('error.html', error_message="Failed to save message.") # Generic error
    else:
        return redirect(url_for('index'))

@app.errorhandler(500)
def internal_server_error(e):
    logging.exception("Internal Server Error")  # Log the full exception on the server
    return render_template('error.html', error_message="An unexpected error occurred."), 500 # Generic error

# Example of rate limiting (using a simple in-memory store)
request_counts = {}
#from datetime import datetime, timedelta #Already imported

@app.before_request
def rate_limit():
    ip_address = request.remote_addr
    now = datetime.now()
    time_window = timedelta(minutes=1)  # Rate limit per minute
    max_requests = 10

    # Clean up old request counts
    request_counts[ip_address] = [ts for ts in request_counts.get(ip_address, []) if now - ts < time_window]

    if len(request_counts.get(ip_address, [])) >= max_requests:
        return "Rate limit exceeded. Please try again later.", 429  # HTTP 429 Too Many Requests

    request_counts.setdefault(ip_address, []).append(now)

# Example of setting a Content Security Policy (CSP)
@app.after_request
def add_csp_header(response):
    # A more practical CSP.  Customize this!
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com;"
    return response

# Session Security
app.config['SESSION_PERMANENT'] = True  # Make sessions persistent
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Protect against CSRF

if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000))) # Disable debug mode in production

