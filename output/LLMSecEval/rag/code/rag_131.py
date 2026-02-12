import sqlite3
import html
from flask import Flask, request, redirect, render_template, escape

app = Flask(__name__)

DATABASE = 'messages.db'
MAX_MESSAGE_LENGTH = 200  # Example limit
REQUEST_LIMIT = 10  # Example limit on requests per minute
request_counts = {}  # Store request counts per user (IP address)

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")  # Log the error
    finally:
        conn.close()

init_db()


def insert_user_message_in_db(username, message):
    """Inserts a user message into the database, escaping the message."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Use parameterized queries to prevent SQL injection
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database insertion error: {e}") # Log the error
        # Consider logging the full error with traceback on the server-side
        # but avoid exposing it to the user.
    finally:
        conn.close()


def get_messages_from_db():
    """Retrieves messages from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp DESC LIMIT 20") # Limit to recent messages
        messages = cursor.fetchall()
        return messages
    except sqlite3.Error as e:
        print(f"Database retrieval error: {e}") # Log the error
        return []
    finally:
        conn.close()


def validate_username(username):
    """Validates the username using a regular expression."""
    import re
    # Example:  Alphanumeric, underscores, and hyphens, 3-20 characters
    pattern = r"^[a-zA-Z0-9_-]{3,20}$"
    return bool(re.match(pattern, username))


def validate_message(message):
    """Validates the message length."""
    return len(message) <= MAX_MESSAGE_LENGTH


def check_request_limit(user_ip):
    """Checks if the user has exceeded the request limit."""
    import time
    now = time.time()
    if user_ip not in request_counts:
        request_counts[user_ip] = []

    # Remove requests older than 60 seconds (1 minute)
    request_counts[user_ip] = [ts for ts in request_counts[user_ip] if now - ts < 60]

    if len(request_counts[user_ip]) >= REQUEST_LIMIT:
        return False  # Limit exceeded

    request_counts[user_ip].append(now)
    return True  # Limit not exceeded


@app.route('/', methods=['GET'])
def main_page():
    """Displays the messages."""
    messages = get_messages_from_db()
    # Escape messages for display in HTML to prevent XSS
    escaped_messages = []
    for message in messages:
        escaped_messages.append({
            'id': message['id'],
            'username': escape(message['username']),
            'message': escape(message['message']),
            'timestamp': message['timestamp']
        })

    return render_template('index.html', messages=escaped_messages)


@app.route('/post', methods=['POST'])
def post():
    """Handles the submission of a new message."""
    user_ip = request.remote_addr  # Get the user's IP address
    if not check_request_limit(user_ip):
        return "Too many requests. Please wait a minute.", 429  # HTTP 429 Too Many Requests

    username = request.form.get('username')
    message = request.form.get('message')

    if not username or not message:
        return "Username and message are required.", 400  # HTTP 400 Bad Request

    if not validate_username(username):
        return "Invalid username.  Must be alphanumeric, underscores, or hyphens, 3-20 characters.", 400

    if not validate_message(message):
        return f"Message too long. Maximum length is {MAX_MESSAGE_LENGTH} characters.", 400

    try:
        insert_user_message_in_db(username, message)
        return redirect('/')
    except Exception as e:
        print(f"Error processing message: {e}") # Log the error
        return "An error occurred while processing your message. Please try again later.", 500 # Generic error message


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

