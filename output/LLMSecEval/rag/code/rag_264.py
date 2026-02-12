import sqlite3
import html
from flask import Flask, request, redirect, render_template, escape

app = Flask(__name__)

# Database setup (replace with your actual database connection details)
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
            message TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()


def insert_user_message_in_db(username, message):
    """Inserts a user message into the database, escaping the message for security."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Sanitize username (example: alphanumeric only, limit length)
        if not username.isalnum() or len(username) > 50:
            raise ValueError("Invalid username format.")

        # Escape the message using a database library routine to prevent SQL injection
        # This is crucial for security!
        cursor.execute("INSERT INTO messages (username, message) VALUES (?, ?)", (username, message))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Log the error on the server
        # Avoid revealing database details to the user.  Return a generic error.
        raise Exception("An error occurred while saving the message.")
    except ValueError as e:
        print(f"Validation error: {e}")
        raise Exception("Invalid input.")
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise Exception("An unexpected error occurred.")


def get_messages_from_db():
    """Retrieves messages from the database, escaping them for HTML display."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, message, timestamp FROM messages ORDER BY timestamp DESC")
        messages = cursor.fetchall()
        conn.close()

        # Escape the messages for HTML output to prevent XSS
        escaped_messages = []
        for message in messages:
            escaped_messages.append({
                'id': message['id'],
                'username': html.escape(message['username']),
                'message': html.escape(message['message']),
                'timestamp': message['timestamp']
            })
        return escaped_messages
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []  # Or handle the error appropriately, e.g., display an error page
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []


@app.route('/', methods=['GET', 'POST'])
def main_page():
    if request.method == 'POST':
        return post()
    else:
        return display_messages()


def post():
    """Handles the submission of a new message."""
    try:
        username = request.form.get('username')
        message = request.form.get('message')

        if not username or not message:
            raise ValueError("Username and message are required.")

        insert_user_message_in_db(username, message)
        return redirect('/')  # Redirect to the main page after posting
    except ValueError as e:
        # Handle validation errors
        error_message = str(e)
        return render_template('index.html', messages=get_messages_from_db(), error=error_message)
    except Exception as e:
        # Handle other errors (e.g., database errors)
        print(f"Error in post(): {e}")  # Log the error
        error_message = "An error occurred while processing your message."  # Generic error message
        return render_template('index.html', messages=get_messages_from_db(), error=error_message)


def display_messages():
    """Displays the messages on the main page."""
    messages = get_messages_from_db()
    return render_template('index.html', messages=messages, error=None)


if __name__ == '__main__':
    app.run(debug=False)  # Disable debug mode in production!

