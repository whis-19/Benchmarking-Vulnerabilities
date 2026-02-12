import sqlite3
from flask import Flask, request, redirect, render_template, g
import secrets
import os

app = Flask(__name__)

# Database Configuration
DATABASE = 'messages.db'

# Secret Key for Session Management (Important for security)
# Generate a strong, random secret key and store it securely (e.g., environment variable)
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(16))  # Fallback to a generated key if not in env
app.secret_key = SECRET_KEY

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
        print(f"Database error: {e}")  # Log the error for debugging
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
def post_message():
    """Handles the posting of a new message."""
    username = request.form.get('username')
    message = request.form.get('message')

    # Input Validation (Crucial for security)
    if not username or not message:
        return "Username and message are required.", 400  # Bad Request

    if len(username) > 50:  # Limit username length
        return "Username too long.", 400

    if len(message) > 500:  # Limit message length
        return "Message too long.", 400

    # Sanitize inputs (Important for security)
    #  -  Consider using a library like bleach for more robust HTML sanitization if you allow any HTML in messages.
    username = username.strip()  # Remove leading/trailing whitespace
    message = message.strip()

    if insert_user_message_in_db(username, message):
        return redirect('/')
    else:
        return "Failed to save message.", 500  # Internal Server Error


# --- Main ---

if __name__ == '__main__':
    # Create the database if it doesn't exist.  This is just for initial setup.
    # In a production environment, you'd likely have a separate deployment/migration process.
    if not os.path.exists(DATABASE):
        init_db()

    # Run the Flask app.  Don't use debug=True in production!
    app.run(debug=True)

