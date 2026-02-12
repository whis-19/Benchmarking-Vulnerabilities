import sqlite3
from flask import Flask, request, redirect, render_template, g, abort
import secrets
import os
import bleach
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import logging
import re
import html

app = Flask(__name__)

# Database Configuration
DATABASE = 'messages.db'

# Secret Key for Session Management (Important for security)
# Generate a strong, random secret key and store it securely (e.g., environment variable)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    print("Warning: FLASK_SECRET_KEY not set.  This is insecure in production.")
    SECRET_KEY = secrets.token_hex(16)  # Fallback for development ONLY
app.secret_key = SECRET_KEY

# CSRF Protection
csrf = CSRFProtect(app)

# Rate Limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],  # Adjust limits as needed
    storage_uri="redis://localhost:6379"  # Use a persistent storage for production (e.g., redis://)
)

# Logging
logging.basicConfig(filename='app.log', level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')


# --- Database Helper Functions ---

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        # Enable foreign key support (important for relational integrity if used)
        db.execute("PRAGMA foreign_keys = ON")
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
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


def insert_user_message_in_db(username, message):
    """Inserts a user message into the database.  Escapes inputs to prevent SQL injection."""
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")  # Log the error for debugging
        db.rollback()  # Rollback the transaction in case of error
        return False  # Indicate failure
    return True  # Indicate success


def get_all_messages():
    """Retrieves all messages from the database."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, message FROM messages ORDER BY id DESC")  # Order by ID for recency
    messages = cursor.fetchall()
    return messages


# --- Routes ---

@app.route('/', methods=['GET'])
def index():
    """Displays the messages."""
    messages = get_all_messages()
    return render_template('index.html', messages=messages)


@app.route('/post', methods=['POST'])
@limiter.limit("5/minute")  # Rate limit: 5 posts per minute
def post_message():
    """Handles the posting of a new message."""
    username = request.form.get('username')
    message = request.form.get('message')

    # Input Validation (Crucial for security)
    if not username or not message:
        abort(400, "Username and message are required.")  # Bad Request

    if len(username) > 50:  # Limit username length
        abort(400, "Username too long.")

    if len(message) > 500:  # Limit message length
        abort(400, "Message too long.")

    # Validate username format
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        abort(400, "Invalid username format.  Only alphanumeric characters and underscores are allowed.")

    # Sanitize inputs (Important for security)
    username = username.strip()  # Remove leading/trailing whitespace
    message = bleach.clean(message.strip(), tags=[], attributes={}, styles=[], strip=True)  # Sanitize with bleach
    message = html.escape(message) # Escape HTML entities

    if insert_user_message_in_db(username, message):
        return redirect('/')
    else:
        logging.error(f"Failed to save message. Username: {username}, Message: {message}")
        abort(500, "Failed to save message due to a server error.")  # Internal Server Error


# --- Error Handling ---

@app.errorhandler(429)
def ratelimit_handler(e):
    return "Rate limit exceeded. Please try again later.", 429

@app.errorhandler(400)
def bad_request_handler(e):
    return str(e), 400  # Return the error message

@app.errorhandler(500)
def internal_server_error_handler(e):
    logging.exception("Internal Server Error")  # Log the full exception
    return "An internal server error occurred. Please try again later.", 500

# --- Main ---

if __name__ == '__main__':
    # Create the database if it doesn't exist.  This is just for initial setup.
    # In a production environment, you'd likely have a separate deployment/migration process.
    if not os.path.exists(DATABASE):
        init_db()

    # Run the Flask app.  Don't use debug=True in production!
    app.run(debug=False)

