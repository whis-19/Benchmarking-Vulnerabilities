import sqlite3
from flask import Flask, request, redirect, render_template, session, escape
import secrets
import logging
import re  # Import the regular expression module

app = Flask(__name__)

# Generate a strong secret key (only do this once and store it securely)
# secret_key = secrets.token_hex(16)
# print(f"Generated secret key: {secret_key}")  # Print it once, then remove this line!
app.secret_key = 'YOUR_SECURE_SECRET_KEY'  # Replace with your actual secret key

DATABASE = 'messages.db'

# Configure logging
logging.basicConfig(filename='app.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the database (create table if it doesn't exist)
def init_db():
    with sqlite3.connect(DATABASE) as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.commit()

init_db()

def get_db_connection():
    """Connects to the database."""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row  # Return rows as dictionaries
    return db

def insert_user_message_in_db(username, message):
    """Inserts a user message into the database, using parameterized queries."""
    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        db.commit()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")  # Log the error
        db.rollback()
        return False
    finally:
        db.close()
    return True

def get_messages_from_db():
    """Retrieves all messages from the database, ordered by timestamp."""
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp DESC")
        messages = cursor.fetchall()
        return messages
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")  # Log the error
        return []
    finally:
        db.close()

def is_valid_username(username):
    # Only allow alphanumeric characters and underscores, 3-20 characters long
    pattern = r"^[a-zA-Z0-9_]{3,20}$"
    return bool(re.match(pattern, username))

def is_valid_message(message):
    # Limit message length and prevent HTML tags
    return len(message) <= 200 and "<" not in message and ">" not in message

@app.route('/', methods=['GET', 'POST'])
def main_page():
    """Handles the main page, displaying messages and processing new posts."""
    if request.method == 'POST':
        return post()

    messages = get_messages_from_db()
    return render_template('index.html', messages=messages, username=session.get('username'))

@app.route('/post', methods=['POST'])
def post():
    """Handles the submission of a new message."""
    if 'username' not in session:
        return redirect('/login')

    username = session['username']
    message = request.form.get('message')

    if not message:
        return "Message cannot be empty.", 400

    if not is_valid_message(message):
        return "Invalid message.  Must be less than 200 characters and cannot contain HTML tags.", 400

    # TODO: Implement CSRF protection here (e.g., using Flask-WTF)

    if insert_user_message_in_db(username, message):
        return redirect('/')
    else:
        return "Failed to save message.", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')

        if not is_valid_username(username):
            return "Invalid username.  Must be 3-20 alphanumeric characters or underscores.", 400

        # TODO: Implement password hashing here (e.g., using bcrypt or scrypt)

        if username:
            session['username'] = username
            return redirect('/')
        else:
            return "Username cannot be empty.", 400
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Handles user logout."""
    session.pop('username', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)

