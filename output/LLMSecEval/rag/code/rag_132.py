from flask import Flask, render_template, request, redirect, url_for, session, escape
import sqlite3
import re
import logging

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong, randomly generated key

# Configure logging
logging.basicConfig(level=logging.ERROR)  # Log errors and above

# Database setup (example using SQLite)
DATABASE = 'messages.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Input validation functions
def is_valid_username(username):
    """Validates username: alphanumeric and underscores only, 3-20 characters."""
    pattern = r"^[a-zA-Z0-9_]{3,20}$"
    return bool(re.match(pattern, username))

def is_valid_message(message):
    """Validates message:  1-200 characters, allows most characters but restricts control characters."""
    pattern = r"^[\x20-\x7E\xA0-\xFF]{1,200}$"  # Allow printable ASCII and extended ASCII
    return bool(re.match(pattern, message))


def insert_user_message_in_db(username, message):
    """Inserts a user message into the database."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        #  Do NOT expose the specific error to the user.  Return a generic message.
        raise Exception("Failed to save message. Please try again later.")


@app.route('/')
def index():
    """Displays messages from the database."""
    try:
        conn = get_db_connection()
        messages = conn.execute('SELECT id, username, message FROM messages').fetchall()
        conn.close()
        return render_template('index.html', messages=[{
            'id': msg['id'],
            'username': escape(msg['username']),  # Escape username
            'message': escape(msg['message'])    # Escape message
        } for msg in messages])
    except Exception as e:
        logging.error(f"Error displaying messages: {e}")
        return render_template('error.html', error_message="Failed to retrieve messages.")


@app.route('/post', methods=['POST'])
def post_message():
    """Handles posting a new message."""
    if request.method == 'POST':
        username = request.form.get('username')
        message = request.form.get('message')

        # Validate inputs
        if not username or not message:
            return render_template('error.html', error_message="Username and message are required.")

        if not is_valid_username(username):
            return render_template('error.html', error_message="Invalid username.  Must be alphanumeric and underscores only, 3-20 characters.")

        if not is_valid_message(message):
            return render_template('error.html', error_message="Invalid message. Must be 1-200 characters and contain only printable characters.")

        try:
            insert_user_message_in_db(username, message)
            return redirect(url_for('index'))
        except Exception as e:
            # Log the error on the server
            logging.error(f"Error inserting message: {e}")
            # Return a generic error message to the user
            return render_template('error.html', error_message="Failed to save message. Please try again later.")

    return redirect(url_for('index'))  # Redirect if not a POST request


@app.errorhandler(500)
def internal_server_error(e):
    """Handles internal server errors."""
    logging.exception("Internal Server Error")  # Log the full exception
    return render_template('error.html', error_message="An unexpected error occurred. Please try again later."), 500


@app.route('/error')
def error():
    """Generic error page."""
    return render_template('error.html', error_message="An error occurred.")


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

